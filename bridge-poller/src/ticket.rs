//! Single-use capability tickets for authorized wave execution.
//!
//! This is a deterministic, hash-chained ledger, not a signature scheme, a
//! consensus protocol, or a zero-knowledge proof. A control ticket retains the
//! revocation capability while execute tickets carry the per-job capability.

use crate::execution::{execute_wave, ExecutionError, WaveExecutionReport};
use crate::ledger::DirectiveLedger;
use crate::wave::{ledger_digest, verify_wave_plan, WaveError, WaveJob, WavePlan};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub const TICKET_LEDGER_SCHEMA_VERSION: &str = "asfa-task-ticket-ledger/v1";
pub const TICKET_ID_DIGEST_DOMAIN: &str = "asfa.task-ticket.id.v1";
pub const TICKET_TRANSACTION_ID_DIGEST_DOMAIN: &str = "asfa.task-ticket-transaction.id.v1";
pub const TICKET_LEDGER_DIGEST_DOMAIN: &str = "asfa.task-ticket-ledger.digest.v1";
pub const DEFAULT_ROOT_TICKET_LIMIT: u64 = 20;
pub const MAX_ROOT_TICKET_LIMIT: u64 = 64;
pub const MAX_TICKETS: usize = 4096;
pub const MAX_TICKET_TRANSACTIONS: usize = 16_384;

fn digest<T: Serialize>(domain: &str, value: &T) -> String {
    let mut encoded = domain.as_bytes().to_vec();
    encoded.extend(serde_json::to_vec(value).expect("ticket projection always serializes"));
    format!("{:x}", Sha256::digest(&encoded))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TicketBody {
    Control { nonce: String, plan_hash: String },
    Execute { job: WaveJob, plan_hash: String },
}

impl TicketBody {
    fn plan_hash(&self) -> &str {
        match self {
            Self::Control { plan_hash, .. } | Self::Execute { plan_hash, .. } => plan_hash,
        }
    }

    fn job(&self) -> Option<&WaveJob> {
        match self {
            Self::Control { .. } => None,
            Self::Execute { job, .. } => Some(job),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TaskTicket {
    pub ticket_id: String,
    pub parent_id: Option<String>,
    pub root_id: Option<String>,
    pub recipient: String,
    pub body: TicketBody,
    pub created_at_epoch: u64,
    pub sequence: u64,
}

#[derive(Serialize)]
struct TicketIdProjection<'a> {
    parent_id: &'a Option<String>,
    root_id: &'a Option<String>,
    recipient: &'a str,
    body: &'a TicketBody,
    created_at_epoch: u64,
    sequence: u64,
}

impl TaskTicket {
    fn control(nonce: &str, plan_hash: &str, controller: &str, now: u64) -> Self {
        let mut ticket = Self {
            ticket_id: String::new(),
            parent_id: None,
            root_id: None,
            recipient: controller.to_owned(),
            body: TicketBody::Control {
                nonce: nonce.to_owned(),
                plan_hash: plan_hash.to_owned(),
            },
            created_at_epoch: now,
            sequence: 0,
        };
        ticket.refresh_id();
        ticket
    }

    fn execute(
        root_id: &str,
        parent_id: &str,
        plan_hash: &str,
        recipient: &str,
        job: &WaveJob,
        now: u64,
        sequence: u64,
    ) -> Self {
        let mut ticket = Self {
            ticket_id: String::new(),
            parent_id: Some(parent_id.to_owned()),
            root_id: Some(root_id.to_owned()),
            recipient: recipient.to_owned(),
            body: TicketBody::Execute {
                job: job.clone(),
                plan_hash: plan_hash.to_owned(),
            },
            created_at_epoch: now,
            sequence,
        };
        ticket.refresh_id();
        ticket
    }

    fn refresh_id(&mut self) {
        self.ticket_id = self.computed_id();
    }

    fn computed_id(&self) -> String {
        digest(
            TICKET_ID_DIGEST_DOMAIN,
            &TicketIdProjection {
                parent_id: &self.parent_id,
                root_id: &self.root_id,
                recipient: &self.recipient,
                body: &self.body,
                created_at_epoch: self.created_at_epoch,
                sequence: self.sequence,
            },
        )
    }

    pub fn has_valid_id(&self) -> bool {
        self.ticket_id == self.computed_id()
    }

    pub fn root_key(&self) -> &str {
        self.root_id.as_deref().unwrap_or(&self.ticket_id)
    }

    pub fn job(&self) -> Option<&WaveJob> {
        self.body.job()
    }

    pub fn plan_hash(&self) -> &str {
        self.body.plan_hash()
    }

    pub fn is_control(&self) -> bool {
        matches!(self.body, TicketBody::Control { .. })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TicketTransactionKind {
    Mint,
    Transfer,
    Execute { plan_hash: String },
    Revoke,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TicketTransaction {
    pub transaction_id: String,
    pub actor: String,
    pub kind: TicketTransactionKind,
    pub inputs: Vec<String>,
    pub outputs: Vec<String>,
    pub created_at_epoch: u64,
}

#[derive(Serialize)]
struct TransactionIdProjection<'a> {
    actor: &'a str,
    kind: &'a TicketTransactionKind,
    inputs: &'a [String],
    outputs: &'a [String],
    created_at_epoch: u64,
}

impl TicketTransaction {
    fn new(
        actor: &str,
        kind: TicketTransactionKind,
        inputs: Vec<String>,
        outputs: Vec<String>,
        now: u64,
    ) -> Self {
        let mut transaction = Self {
            transaction_id: String::new(),
            actor: actor.to_owned(),
            kind,
            inputs,
            outputs,
            created_at_epoch: now,
        };
        transaction.transaction_id = transaction.computed_id();
        transaction
    }

    fn computed_id(&self) -> String {
        digest(
            TICKET_TRANSACTION_ID_DIGEST_DOMAIN,
            &TransactionIdProjection {
                actor: &self.actor,
                kind: &self.kind,
                inputs: &self.inputs,
                outputs: &self.outputs,
                created_at_epoch: self.created_at_epoch,
            },
        )
    }

    pub fn has_valid_id(&self) -> bool {
        self.transaction_id == self.computed_id()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TicketLedgerSnapshot {
    pub schema_version: String,
    pub network_name: String,
    pub policy_hash: String,
    pub root_ticket_limit: u64,
    pub tickets: Vec<TaskTicket>,
    pub transactions: Vec<TicketTransaction>,
}

#[derive(Clone, Debug)]
pub struct TicketLedger {
    network_name: String,
    policy_hash: String,
    root_ticket_limit: u64,
    tickets: BTreeMap<String, TaskTicket>,
    transactions: BTreeMap<String, TicketTransaction>,
    spent: BTreeMap<String, String>,
}

impl Default for TicketLedger {
    fn default() -> Self {
        Self {
            network_name: String::new(),
            policy_hash: String::new(),
            root_ticket_limit: DEFAULT_ROOT_TICKET_LIMIT,
            tickets: BTreeMap::new(),
            transactions: BTreeMap::new(),
            spent: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TicketError {
    #[error("ticket field must not be empty: {0}")]
    EmptyField(&'static str),
    #[error("ticket ledger is not bound to a registry")]
    Unbound,
    #[error("ticket ledger registry binding mismatch")]
    Binding,
    #[error("invalid wave plan for ticket ledger: {0}")]
    InvalidPlan(String),
    #[error("unknown ticket: {0}")]
    UnknownTicket(String),
    #[error("ticket is not live: {0}")]
    NotLive(String),
    #[error("ticket recipient mismatch for {ticket_id}: actor={actor}")]
    WrongRecipient { ticket_id: String, actor: String },
    #[error("ticket is not an execute ticket: {0}")]
    NotExecuteTicket(String),
    #[error("ticket is not a root control ticket: {0}")]
    NotControlTicket(String),
    #[error("duplicate wave job in ticket history: {session}/{id}")]
    DuplicateJob { session: String, id: String },
    #[error("root ticket budget exceeded: root={root_id}, limit={limit}")]
    RootBudget { root_id: String, limit: u64 },
    #[error("ticket plan binding mismatch: {0}")]
    PlanBinding(String),
    #[error("execution history binding mismatch: {0}")]
    ExecutionHistory(String),
    #[error("invalid ticket snapshot: {0}")]
    InvalidSnapshot(String),
}

#[derive(Debug, Error)]
pub enum TicketedExecutionError {
    #[error(transparent)]
    Ticket(#[from] TicketError),
    #[error(transparent)]
    Execution(#[from] ExecutionError),
    #[error(transparent)]
    Wave(#[from] WaveError),
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TicketedExecutionOutcome {
    pub execution: WaveExecutionReport,
    pub transaction: Option<TicketTransaction>,
    pub replayed: bool,
}

impl TicketLedger {
    pub fn is_empty(&self) -> bool {
        self.tickets.is_empty() && self.transactions.is_empty()
    }

    pub fn network_name(&self) -> &str {
        &self.network_name
    }

    pub fn policy_hash(&self) -> &str {
        &self.policy_hash
    }

    pub fn root_ticket_limit(&self) -> u64 {
        self.root_ticket_limit
    }

    pub fn len(&self) -> usize {
        self.tickets.len()
    }

    pub fn transaction_len(&self) -> usize {
        self.transactions.len()
    }

    pub fn ticket(&self, ticket_id: &str) -> Option<&TaskTicket> {
        self.tickets.get(ticket_id)
    }

    pub fn transaction(&self, transaction_id: &str) -> Option<&TicketTransaction> {
        self.transactions.get(transaction_id)
    }

    pub fn tickets(&self) -> impl Iterator<Item = &TaskTicket> {
        self.tickets.values()
    }

    pub fn transactions(&self) -> impl Iterator<Item = &TicketTransaction> {
        self.transactions.values()
    }

    pub fn ticket_for_job(&self, session: &str, id: &str) -> Option<&TaskTicket> {
        self.tickets
            .values()
            .filter(|ticket| {
                ticket
                    .job()
                    .is_some_and(|job| job.session == session && job.id == id)
            })
            .max_by_key(|ticket| ticket.sequence)
    }

    pub fn spending_transaction(&self, ticket_id: &str) -> Option<&TicketTransaction> {
        self.spent
            .get(ticket_id)
            .and_then(|transaction_id| self.transactions.get(transaction_id))
    }

    pub fn is_live(&self, ticket_id: &str) -> bool {
        let Some(ticket) = self.tickets.get(ticket_id) else {
            return false;
        };
        if self.spent.contains_key(ticket_id) {
            return false;
        }
        if ticket.is_control() {
            return true;
        }
        !self.spent.contains_key(ticket.root_key())
    }

    fn ensure_binding(&mut self, network_name: &str, policy_hash: &str) -> Result<(), TicketError> {
        if network_name.trim().is_empty() {
            return Err(TicketError::EmptyField("network_name"));
        }
        if policy_hash.len() != 64 || !policy_hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(TicketError::EmptyField("policy_hash"));
        }
        if self.is_empty() {
            self.network_name = network_name.to_owned();
            self.policy_hash = policy_hash.to_owned();
        }
        if self.network_name != network_name || self.policy_hash != policy_hash {
            return Err(TicketError::Binding);
        }
        Ok(())
    }

    fn next_sequence(&self, root_id: &str) -> Result<u64, TicketError> {
        let count = self
            .tickets
            .values()
            .filter(|ticket| ticket.root_key() == root_id)
            .count() as u64;
        if count >= self.root_ticket_limit {
            return Err(TicketError::RootBudget {
                root_id: root_id.to_owned(),
                limit: self.root_ticket_limit,
            });
        }
        Ok(count)
    }

    fn commit(
        &mut self,
        transaction: TicketTransaction,
        created: Vec<TaskTicket>,
    ) -> Result<TicketTransaction, TicketError> {
        if self.transactions.len() >= MAX_TICKET_TRANSACTIONS
            || self.tickets.len() + created.len() > MAX_TICKETS
        {
            return Err(TicketError::InvalidSnapshot(
                "ticket capacity exceeded".to_owned(),
            ));
        }
        let mut staged = self.clone();
        for input in &transaction.inputs {
            if !staged.is_live(input) {
                return Err(TicketError::NotLive(input.clone()));
            }
            if staged
                .spent
                .insert(input.clone(), transaction.transaction_id.clone())
                .is_some()
            {
                return Err(TicketError::NotLive(input.clone()));
            }
        }
        for ticket in created {
            if staged
                .tickets
                .insert(ticket.ticket_id.clone(), ticket)
                .is_some()
            {
                return Err(TicketError::InvalidSnapshot(
                    "duplicate ticket identifier".to_owned(),
                ));
            }
        }
        if staged
            .transactions
            .insert(transaction.transaction_id.clone(), transaction.clone())
            .is_some()
        {
            return Err(TicketError::InvalidSnapshot(
                "duplicate transaction identifier".to_owned(),
            ));
        }
        staged.verify()?;
        *self = staged;
        Ok(transaction)
    }

    fn mint(
        &mut self,
        plan: &WavePlan,
        nonce: &str,
        controller: &str,
        agent: &str,
        now: u64,
    ) -> Result<TicketTransaction, TicketError> {
        self.ensure_binding(&plan.network_name, &plan.policy_hash)?;
        verify_wave_plan(plan).map_err(|error| TicketError::InvalidPlan(error.to_string()))?;
        for (field, value) in [
            ("nonce", nonce),
            ("controller", controller),
            ("agent", agent),
        ] {
            if value.trim().is_empty() {
                return Err(TicketError::EmptyField(field));
            }
        }
        for job in &plan.jobs {
            if self.ticket_for_job(&job.session, &job.id).is_some() {
                return Err(TicketError::DuplicateJob {
                    session: job.session.clone(),
                    id: job.id.clone(),
                });
            }
        }
        let root = TaskTicket::control(nonce, &plan.plan_hash, controller, now);
        if plan.jobs.len() as u64 + 1 > self.root_ticket_limit {
            return Err(TicketError::RootBudget {
                root_id: root.ticket_id,
                limit: self.root_ticket_limit,
            });
        }
        let mut created = vec![root.clone()];
        for (index, job) in plan.jobs.iter().enumerate() {
            created.push(TaskTicket::execute(
                &root.ticket_id,
                &root.ticket_id,
                &plan.plan_hash,
                agent,
                job,
                now,
                index as u64 + 1,
            ));
        }
        let outputs = created
            .iter()
            .map(|ticket| ticket.ticket_id.clone())
            .collect();
        let transaction = TicketTransaction::new(
            controller,
            TicketTransactionKind::Mint,
            Vec::new(),
            outputs,
            now,
        );
        self.commit(transaction, created)
    }

    pub fn transfer(
        &mut self,
        ticket_id: &str,
        actor: &str,
        new_recipient: &str,
        now: u64,
    ) -> Result<TicketTransaction, TicketError> {
        let ticket = self
            .tickets
            .get(ticket_id)
            .cloned()
            .ok_or_else(|| TicketError::UnknownTicket(ticket_id.to_owned()))?;
        if ticket.recipient != actor {
            return Err(TicketError::WrongRecipient {
                ticket_id: ticket_id.to_owned(),
                actor: actor.to_owned(),
            });
        }
        if !self.is_live(ticket_id) {
            return Err(TicketError::NotLive(ticket_id.to_owned()));
        }
        let Some(job) = ticket.job().cloned() else {
            return Err(TicketError::NotExecuteTicket(ticket_id.to_owned()));
        };
        if new_recipient.trim().is_empty() {
            return Err(TicketError::EmptyField("new_recipient"));
        }
        let root_id = ticket.root_key().to_owned();
        let sequence = self.next_sequence(&root_id)?;
        let child = TaskTicket::execute(
            &root_id,
            ticket_id,
            ticket.plan_hash(),
            new_recipient,
            &job,
            now,
            sequence,
        );
        let transaction = TicketTransaction::new(
            actor,
            TicketTransactionKind::Transfer,
            vec![ticket_id.to_owned()],
            vec![child.ticket_id.clone()],
            now,
        );
        self.commit(transaction, vec![child])
    }

    pub fn revoke(
        &mut self,
        root_id: &str,
        actor: &str,
        now: u64,
    ) -> Result<TicketTransaction, TicketError> {
        let root = self
            .tickets
            .get(root_id)
            .cloned()
            .ok_or_else(|| TicketError::UnknownTicket(root_id.to_owned()))?;
        if !root.is_control() || root.root_id.is_some() {
            return Err(TicketError::NotControlTicket(root_id.to_owned()));
        }
        if root.recipient != actor {
            return Err(TicketError::WrongRecipient {
                ticket_id: root_id.to_owned(),
                actor: actor.to_owned(),
            });
        }
        if !self.is_live(root_id) {
            return Err(TicketError::NotLive(root_id.to_owned()));
        }
        let transaction = TicketTransaction::new(
            actor,
            TicketTransactionKind::Revoke,
            vec![root_id.to_owned()],
            Vec::new(),
            now,
        );
        self.commit(transaction, Vec::new())
    }

    fn spend_for_execution(
        &mut self,
        ticket_ids: &[String],
        actor: &str,
        plan_hash: &str,
        now: u64,
    ) -> Result<TicketTransaction, TicketError> {
        if ticket_ids.is_empty() {
            return Err(TicketError::InvalidPlan(
                "execution requires at least one ticket".to_owned(),
            ));
        }
        for ticket_id in ticket_ids {
            let ticket = self
                .tickets
                .get(ticket_id)
                .ok_or_else(|| TicketError::UnknownTicket(ticket_id.clone()))?;
            if !ticket.is_control() && ticket.plan_hash() == plan_hash {
                if ticket.recipient != actor {
                    return Err(TicketError::WrongRecipient {
                        ticket_id: ticket_id.clone(),
                        actor: actor.to_owned(),
                    });
                }
                if !self.is_live(ticket_id) {
                    return Err(TicketError::NotLive(ticket_id.clone()));
                }
            } else {
                return Err(TicketError::PlanBinding(ticket_id.clone()));
            }
        }
        let transaction = TicketTransaction::new(
            actor,
            TicketTransactionKind::Execute {
                plan_hash: plan_hash.to_owned(),
            },
            ticket_ids.to_vec(),
            Vec::new(),
            now,
        );
        self.commit(transaction, Vec::new())
    }

    fn verify_execution_replay(
        &self,
        ticket_ids: &[String],
        actor: &str,
        plan_hash: &str,
    ) -> Result<(), TicketError> {
        let mut spending_ids = BTreeSet::new();
        for ticket_id in ticket_ids {
            let transaction = self.spending_transaction(ticket_id).ok_or_else(|| {
                TicketError::ExecutionHistory(format!("ticket is still unspent: {ticket_id}"))
            })?;
            if transaction.actor != actor
                || transaction.kind
                    != (TicketTransactionKind::Execute {
                        plan_hash: plan_hash.to_owned(),
                    })
            {
                return Err(TicketError::ExecutionHistory(ticket_id.clone()));
            }
            spending_ids.insert(transaction.transaction_id.clone());
        }
        if spending_ids.len() != 1 {
            return Err(TicketError::ExecutionHistory(
                "wave tickets were not consumed by one transaction".to_owned(),
            ));
        }
        let transaction_id = spending_ids.into_iter().next().expect("one transaction");
        let transaction = self
            .transactions
            .get(&transaction_id)
            .expect("spending transaction exists");
        let expected: BTreeSet<_> = ticket_ids.iter().cloned().collect();
        let actual: BTreeSet<_> = transaction.inputs.iter().cloned().collect();
        if actual != expected || actual.len() != transaction.inputs.len() {
            return Err(TicketError::ExecutionHistory(
                "execute transaction input set mismatch".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn snapshot(&self) -> TicketLedgerSnapshot {
        TicketLedgerSnapshot {
            schema_version: TICKET_LEDGER_SCHEMA_VERSION.to_owned(),
            network_name: self.network_name.clone(),
            policy_hash: self.policy_hash.clone(),
            root_ticket_limit: self.root_ticket_limit,
            tickets: self.tickets.values().cloned().collect(),
            transactions: self.transactions.values().cloned().collect(),
        }
    }

    pub fn digest(&self) -> String {
        digest(TICKET_LEDGER_DIGEST_DOMAIN, &self.snapshot())
    }

    pub fn from_snapshot(snapshot: TicketLedgerSnapshot) -> Result<Self, TicketError> {
        if snapshot.schema_version != TICKET_LEDGER_SCHEMA_VERSION {
            return Err(TicketError::InvalidSnapshot(format!(
                "unsupported schema: {}",
                snapshot.schema_version
            )));
        }
        if snapshot.tickets.len() > MAX_TICKETS
            || snapshot.transactions.len() > MAX_TICKET_TRANSACTIONS
        {
            return Err(TicketError::InvalidSnapshot(
                "snapshot capacity exceeded".to_owned(),
            ));
        }
        if snapshot.root_ticket_limit == 0 || snapshot.root_ticket_limit > MAX_ROOT_TICKET_LIMIT {
            return Err(TicketError::InvalidSnapshot(
                "invalid root ticket limit".to_owned(),
            ));
        }
        let mut tickets = BTreeMap::new();
        for ticket in snapshot.tickets {
            if tickets
                .insert(ticket.ticket_id.clone(), ticket.clone())
                .is_some()
            {
                return Err(TicketError::InvalidSnapshot(format!(
                    "duplicate ticket identifier: {}",
                    ticket.ticket_id
                )));
            }
        }
        let mut transactions = BTreeMap::new();
        for transaction in snapshot.transactions {
            if transactions
                .insert(transaction.transaction_id.clone(), transaction.clone())
                .is_some()
            {
                return Err(TicketError::InvalidSnapshot(format!(
                    "duplicate transaction identifier: {}",
                    transaction.transaction_id
                )));
            }
        }
        let mut spent = BTreeMap::new();
        for transaction in transactions.values() {
            for input in &transaction.inputs {
                if spent
                    .insert(input.clone(), transaction.transaction_id.clone())
                    .is_some()
                {
                    return Err(TicketError::InvalidSnapshot(format!(
                        "ticket consumed more than once: {input}"
                    )));
                }
            }
        }
        let ledger = Self {
            network_name: snapshot.network_name,
            policy_hash: snapshot.policy_hash,
            root_ticket_limit: snapshot.root_ticket_limit,
            tickets,
            transactions,
            spent,
        };
        ledger.verify()?;
        Ok(ledger)
    }

    fn verify_not_revoked(
        &self,
        ticket: &TaskTicket,
        transaction: &TicketTransaction,
    ) -> Result<(), TicketError> {
        if let Some(revoke_id) = self.spent.get(ticket.root_key()) {
            let revoke = &self.transactions[revoke_id];
            if matches!(revoke.kind, TicketTransactionKind::Revoke)
                && revoke.created_at_epoch <= transaction.created_at_epoch
            {
                return Err(TicketError::InvalidSnapshot(
                    "descendant transaction at or after root revocation".to_owned(),
                ));
            }
        }
        Ok(())
    }

    pub fn verify(&self) -> Result<(), TicketError> {
        if self.network_name.trim().is_empty() || !valid_digest(&self.policy_hash) {
            return Err(TicketError::Unbound);
        }
        if self.root_ticket_limit == 0 || self.root_ticket_limit > MAX_ROOT_TICKET_LIMIT {
            return Err(TicketError::InvalidSnapshot(
                "invalid root ticket limit".to_owned(),
            ));
        }
        if self.tickets.len() > MAX_TICKETS || self.transactions.len() > MAX_TICKET_TRANSACTIONS {
            return Err(TicketError::InvalidSnapshot(
                "ticket capacity exceeded".to_owned(),
            ));
        }
        let mut created_by = BTreeMap::new();
        let mut expected_spent = BTreeMap::new();
        let mut job_tickets = BTreeMap::new();
        let mut job_bases = BTreeMap::new();
        for ticket in self.tickets.values() {
            if !ticket.has_valid_id() || ticket.recipient.trim().is_empty() {
                return Err(TicketError::InvalidSnapshot(format!(
                    "invalid ticket identifier or recipient: {}",
                    ticket.ticket_id
                )));
            }
            if !valid_digest(ticket.plan_hash()) {
                return Err(TicketError::InvalidSnapshot(
                    "invalid ticket plan hash".to_owned(),
                ));
            }
            match &ticket.body {
                TicketBody::Control { nonce, .. } => {
                    if nonce.trim().is_empty()
                        || ticket.parent_id.is_some()
                        || ticket.root_id.is_some()
                        || ticket.sequence != 0
                    {
                        return Err(TicketError::InvalidSnapshot(format!(
                            "invalid root control ticket: {}",
                            ticket.ticket_id
                        )));
                    }
                }
                TicketBody::Execute { job, .. } => {
                    if job.session.trim().is_empty() || job.id.trim().is_empty() {
                        return Err(TicketError::InvalidSnapshot("empty job binding".to_owned()));
                    }
                    let (Some(parent_id), Some(root_id)) = (&ticket.parent_id, &ticket.root_id)
                    else {
                        return Err(TicketError::InvalidSnapshot(
                            "execute ticket lacks lineage".to_owned(),
                        ));
                    };
                    let root = self.tickets.get(root_id).ok_or_else(|| {
                        TicketError::InvalidSnapshot("missing root ticket".to_owned())
                    })?;
                    if !root.is_control() || root.plan_hash() != ticket.plan_hash() {
                        return Err(TicketError::InvalidSnapshot(
                            "root plan binding mismatch".to_owned(),
                        ));
                    }
                    let parent = self.tickets.get(parent_id).ok_or_else(|| {
                        TicketError::InvalidSnapshot("missing parent ticket".to_owned())
                    })?;
                    if ticket.sequence == 0
                        || parent.sequence >= ticket.sequence
                        || parent.created_at_epoch > ticket.created_at_epoch
                    {
                        return Err(TicketError::InvalidSnapshot(
                            "invalid parent sequence or timestamp".to_owned(),
                        ));
                    }
                    let key = (job.session.clone(), job.id.clone());
                    if parent_id == root_id {
                        *job_bases.entry(key.clone()).or_insert(0_usize) += 1;
                    } else if parent.job() != Some(job) {
                        return Err(TicketError::InvalidSnapshot(
                            "parent belongs to a different job chain".to_owned(),
                        ));
                    }
                    if job_tickets
                        .insert(key, ticket.root_key().to_owned())
                        .is_some_and(|existing_root| existing_root != ticket.root_key())
                    {
                        return Err(TicketError::DuplicateJob {
                            session: job.session.clone(),
                            id: job.id.clone(),
                        });
                    }
                }
            }
        }
        if job_bases.len() != job_tickets.len()
            || job_bases.values().any(|base_count| *base_count != 1)
        {
            return Err(TicketError::InvalidSnapshot(
                "each job must have exactly one mint base ticket".to_owned(),
            ));
        }
        for transaction in self.transactions.values() {
            if !transaction.has_valid_id() || transaction.actor.trim().is_empty() {
                return Err(TicketError::InvalidSnapshot(format!(
                    "invalid transaction identifier or actor: {}",
                    transaction.transaction_id
                )));
            }
            let input_set: BTreeSet<_> = transaction.inputs.iter().collect();
            let output_set: BTreeSet<_> = transaction.outputs.iter().collect();
            if input_set.len() != transaction.inputs.len()
                || output_set.len() != transaction.outputs.len()
            {
                return Err(TicketError::InvalidSnapshot(
                    "duplicate transaction input or output".to_owned(),
                ));
            }
            for input in &transaction.inputs {
                let ticket = self.tickets.get(input).ok_or_else(|| {
                    TicketError::InvalidSnapshot("transaction input is missing".to_owned())
                })?;
                if ticket.created_at_epoch > transaction.created_at_epoch {
                    return Err(TicketError::InvalidSnapshot(
                        "transaction predates its input".to_owned(),
                    ));
                }
                if expected_spent
                    .insert(input.clone(), transaction.transaction_id.clone())
                    .is_some()
                {
                    return Err(TicketError::InvalidSnapshot(
                        "ticket consumed more than once".to_owned(),
                    ));
                }
            }
            for output in &transaction.outputs {
                let ticket = self.tickets.get(output).ok_or_else(|| {
                    TicketError::InvalidSnapshot("transaction output is missing".to_owned())
                })?;
                if ticket.created_at_epoch != transaction.created_at_epoch {
                    return Err(TicketError::InvalidSnapshot(
                        "output timestamp mismatch".to_owned(),
                    ));
                }
                if created_by
                    .insert(output.clone(), transaction.transaction_id.clone())
                    .is_some()
                {
                    return Err(TicketError::InvalidSnapshot(
                        "ticket created more than once".to_owned(),
                    ));
                }
            }
            match &transaction.kind {
                TicketTransactionKind::Mint => {
                    if !transaction.inputs.is_empty() || transaction.outputs.len() < 2 {
                        return Err(TicketError::InvalidSnapshot(
                            "invalid mint shape".to_owned(),
                        ));
                    }
                    let root = &self.tickets[&transaction.outputs[0]];
                    if !root.is_control() || root.recipient != transaction.actor {
                        return Err(TicketError::InvalidSnapshot(
                            "invalid mint controller".to_owned(),
                        ));
                    }
                    for (index, output) in transaction.outputs[1..].iter().enumerate() {
                        let ticket = &self.tickets[output];
                        if ticket.is_control()
                            || ticket.parent_id.as_deref() != Some(&root.ticket_id)
                            || ticket.root_id.as_deref() != Some(&root.ticket_id)
                            || ticket.sequence != index as u64 + 1
                            || ticket.plan_hash() != root.plan_hash()
                        {
                            return Err(TicketError::InvalidSnapshot(
                                "invalid mint execute output".to_owned(),
                            ));
                        }
                    }
                    if transaction.outputs.len() as u64 > self.root_ticket_limit {
                        return Err(TicketError::RootBudget {
                            root_id: root.ticket_id.clone(),
                            limit: self.root_ticket_limit,
                        });
                    }
                }
                TicketTransactionKind::Transfer => {
                    if transaction.inputs.len() != 1 || transaction.outputs.len() != 1 {
                        return Err(TicketError::InvalidSnapshot(
                            "invalid transfer shape".to_owned(),
                        ));
                    }
                    let parent = &self.tickets[&transaction.inputs[0]];
                    let child = &self.tickets[&transaction.outputs[0]];
                    if parent.is_control()
                        || child.is_control()
                        || parent.recipient != transaction.actor
                        || child.parent_id.as_deref() != Some(&parent.ticket_id)
                        || child.root_key() != parent.root_key()
                        || child.plan_hash() != parent.plan_hash()
                        || child.job() != parent.job()
                        || child.sequence <= parent.sequence
                    {
                        return Err(TicketError::InvalidSnapshot(
                            "invalid transfer lineage".to_owned(),
                        ));
                    }
                    self.verify_not_revoked(parent, transaction)?;
                }
                TicketTransactionKind::Execute { plan_hash } => {
                    if !valid_digest(plan_hash)
                        || transaction.inputs.is_empty()
                        || !transaction.outputs.is_empty()
                    {
                        return Err(TicketError::InvalidSnapshot(
                            "invalid execute shape".to_owned(),
                        ));
                    }
                    for input in &transaction.inputs {
                        let ticket = &self.tickets[input];
                        if ticket.is_control()
                            || ticket.recipient != transaction.actor
                            || ticket.plan_hash() != plan_hash
                        {
                            return Err(TicketError::InvalidSnapshot(
                                "invalid execute authorization".to_owned(),
                            ));
                        }
                        self.verify_not_revoked(ticket, transaction)?;
                    }
                }
                TicketTransactionKind::Revoke => {
                    if transaction.inputs.len() != 1 || !transaction.outputs.is_empty() {
                        return Err(TicketError::InvalidSnapshot(
                            "invalid revoke shape".to_owned(),
                        ));
                    }
                    let root = &self.tickets[&transaction.inputs[0]];
                    if !root.is_control()
                        || root.root_id.is_some()
                        || root.recipient != transaction.actor
                    {
                        return Err(TicketError::InvalidSnapshot(
                            "invalid revoke authorization".to_owned(),
                        ));
                    }
                }
            }
        }
        if created_by.len() != self.tickets.len() {
            return Err(TicketError::InvalidSnapshot(
                "ticket lacks a creating transaction".to_owned(),
            ));
        }
        if expected_spent != self.spent {
            return Err(TicketError::InvalidSnapshot(
                "spent index mismatch".to_owned(),
            ));
        }
        let mut sequences = BTreeMap::<String, Vec<u64>>::new();
        for ticket in self.tickets.values() {
            sequences
                .entry(ticket.root_key().to_owned())
                .or_default()
                .push(ticket.sequence);
        }
        for (root_id, mut values) in sequences {
            values.sort_unstable();
            if values.iter().copied().ne(0..values.len() as u64)
                || values.len() as u64 > self.root_ticket_limit
            {
                return Err(TicketError::InvalidSnapshot(format!(
                    "non-contiguous or over-budget root sequence: {root_id}"
                )));
            }
        }
        Ok(())
    }
}

pub fn ticket_ledger_digest(ledger: &DirectiveLedger) -> Option<String> {
    (!ledger.tickets().is_empty()).then(|| ledger.tickets().digest())
}

pub fn mint_wave_tickets(
    ledger: &mut DirectiveLedger,
    plan: &WavePlan,
    nonce: &str,
    controller: &str,
    agent: &str,
    now: u64,
) -> Result<TicketTransaction, TicketError> {
    if plan.ledger_hash != ledger_digest(ledger) {
        return Err(TicketError::PlanBinding(
            "plan does not bind the current directive ledger".to_owned(),
        ));
    }
    if ledger.network_name() != Some(plan.network_name.as_str())
        || ledger.policy_hash() != Some(plan.policy_hash.as_str())
    {
        return Err(TicketError::Binding);
    }
    let mut staged = ledger.clone();
    let transaction = staged
        .tickets_mut()
        .mint(plan, nonce, controller, agent, now)?;
    *ledger = staged;
    Ok(transaction)
}

pub fn execute_ticketed_wave(
    ledger: &mut DirectiveLedger,
    plan: &WavePlan,
    agent: &str,
    now: u64,
) -> Result<TicketedExecutionOutcome, TicketedExecutionError> {
    verify_wave_plan(plan)?;
    if ledger.network_name() != Some(plan.network_name.as_str())
        || ledger.policy_hash() != Some(plan.policy_hash.as_str())
    {
        return Err(TicketError::Binding.into());
    }
    let mut ticket_ids = Vec::with_capacity(plan.jobs.len());
    for job in &plan.jobs {
        let ticket = ledger
            .tickets()
            .ticket_for_job(&job.session, &job.id)
            .ok_or_else(|| TicketError::UnknownTicket(format!("{}/{}", job.session, job.id)))?;
        if ticket.plan_hash() != plan.plan_hash {
            return Err(TicketError::PlanBinding(ticket.ticket_id.clone()).into());
        }
        ticket_ids.push(ticket.ticket_id.clone());
    }
    let spent_count = ticket_ids
        .iter()
        .filter(|ticket_id| ledger.tickets().spending_transaction(ticket_id).is_some())
        .count();
    if spent_count == ticket_ids.len() {
        ledger
            .tickets()
            .verify_execution_replay(&ticket_ids, agent, &plan.plan_hash)?;
        ledger.verify_ticket_execution_history()?;
        let before = ticket_ledger_digest(ledger);
        let execution = execute_wave(ledger, plan, now)?;
        if ticket_ledger_digest(ledger) != before {
            return Err(TicketError::ExecutionHistory(
                "replay mutated the ticket ledger".to_owned(),
            )
            .into());
        }
        return Ok(TicketedExecutionOutcome {
            execution,
            transaction: None,
            replayed: true,
        });
    }
    if spent_count != 0 {
        return Err(TicketError::ExecutionHistory(
            "partially spent wave cannot execute".to_owned(),
        )
        .into());
    }
    for ticket_id in &ticket_ids {
        let ticket = ledger
            .tickets()
            .ticket(ticket_id)
            .expect("collected ticket exists");
        if ticket.recipient != agent {
            return Err(TicketError::WrongRecipient {
                ticket_id: ticket_id.clone(),
                actor: agent.to_owned(),
            }
            .into());
        }
        if !ledger.tickets().is_live(ticket_id) {
            return Err(TicketError::NotLive(ticket_id.clone()).into());
        }
    }
    let mut staged = ledger.clone();
    let execution = execute_wave(&mut staged, plan, now)?;
    let transaction =
        staged
            .tickets_mut()
            .spend_for_execution(&ticket_ids, agent, &plan.plan_hash, now)?;
    staged.verify_ticket_execution_history()?;
    *ledger = staged;
    Ok(TicketedExecutionOutcome {
        execution,
        transaction: Some(transaction),
        replayed: false,
    })
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TicketOperationReport {
    pub schema_version: String,
    pub operation: String,
    pub transaction: Option<TicketTransaction>,
    pub replayed: bool,
    pub ticket_count: usize,
    pub transaction_count: usize,
    pub ticket_ledger_hash: String,
}

impl TicketOperationReport {
    pub fn new(
        operation: &str,
        transaction: Option<TicketTransaction>,
        replayed: bool,
        ledger: &TicketLedger,
    ) -> Self {
        Self {
            schema_version: "asfa-ticket-operation/v1".into(),
            operation: operation.into(),
            transaction,
            replayed,
            ticket_count: ledger.len(),
            transaction_count: ledger.transaction_len(),
            ticket_ledger_hash: ledger.digest(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::{LEDGER_SCHEMA_VERSION, TICKETED_LEDGER_SCHEMA_VERSION};
    use crate::model::{Directive, Registry};
    use crate::wave::{compute_wave_plan_hash, plan_wave};
    use crate::IngestOutcome;
    use serde_json::json;
    use std::collections::BTreeMap;

    fn registry() -> Registry {
        Registry {
            schema_version: "test".into(),
            network_name: "alpha".into(),
            trust_model: "unsigned-hash-chain".into(),
            sessions: BTreeMap::new(),
        }
    }

    fn directive(id: &str, action: &str, payload: serde_json::Value) -> Directive {
        Directive {
            id: id.into(),
            from: "node".into(),
            to: "qfos".into(),
            action: action.into(),
            payload,
            expires_epoch: None,
        }
    }

    fn admit(ledger: &mut DirectiveLedger, directive: Directive) {
        assert_eq!(ledger.ingest("node", directive, 1), IngestOutcome::Inserted);
    }

    fn one_job_ledger() -> DirectiveLedger {
        let mut ledger = DirectiveLedger::for_registry(&registry());
        admit(
            &mut ledger,
            directive("sum", "engine.sum", json!({"values": [20, 22]})),
        );
        ledger
    }

    fn plan(ledger: &DirectiveLedger) -> WavePlan {
        plan_wave(ledger, "qfos", 50, 16, 16).unwrap()
    }

    fn snapshot_bytes(ledger: &DirectiveLedger) -> Vec<u8> {
        serde_json::to_vec(&ledger.snapshot()).unwrap()
    }

    #[test]
    fn mint_execute_restore_and_replay_form_one_atomic_history() {
        let mut ledger = one_job_ledger();
        admit(
            &mut ledger,
            directive("sha", "engine.sha256", json!({"text": "abc"})),
        );
        let plan = plan(&ledger);
        let v4 = serde_json::to_string(&ledger.snapshot()).unwrap();
        assert!(v4.contains(LEDGER_SCHEMA_VERSION));
        assert!(!v4.contains("\"tickets\""));

        let mint =
            mint_wave_tickets(&mut ledger, &plan, "root-nonce", "root", "alice", 100).unwrap();
        assert_eq!(mint.outputs.len(), 3);
        assert_eq!(ledger.tickets().len(), 3);
        assert_eq!(ledger.tickets().transaction_len(), 1);
        assert_eq!(
            ledger.snapshot().schema_version,
            TICKETED_LEDGER_SCHEMA_VERSION
        );
        let restored = DirectiveLedger::from_snapshot(ledger.snapshot()).unwrap();
        assert_eq!(snapshot_bytes(&restored), snapshot_bytes(&ledger));

        let executed = execute_ticketed_wave(&mut ledger, &plan, "alice", 200).unwrap();
        assert!(!executed.replayed);
        assert!(executed.transaction.is_some());
        assert_eq!(executed.execution.summary.succeeded, 2);
        assert_eq!(ledger.receipt_len(), 2);
        assert_eq!(ledger.len(), 0);
        assert_eq!(ledger.consumed_len(), 2);
        ledger.verify_ticket_execution_history().unwrap();
        let after = snapshot_bytes(&ledger);
        let restored = DirectiveLedger::from_snapshot(ledger.snapshot()).unwrap();
        assert_eq!(snapshot_bytes(&restored), after);

        let replay = execute_ticketed_wave(&mut ledger, &plan, "alice", 201).unwrap();
        assert!(replay.replayed);
        assert!(replay.transaction.is_none());
        assert_eq!(replay.execution.summary.skipped_succeeded, 2);
        assert_eq!(snapshot_bytes(&ledger), after);
        assert_eq!(ledger.tickets().transaction_len(), 2);
    }

    #[test]
    fn wrong_recipient_stale_plan_duplicate_mint_and_double_spend_do_not_mutate() {
        let mut ledger = one_job_ledger();
        let plan = plan(&ledger);
        mint_wave_tickets(&mut ledger, &plan, "root-nonce", "root", "alice", 100).unwrap();
        let ticket_id = ledger
            .tickets()
            .ticket_for_job("node", "sum")
            .unwrap()
            .ticket_id
            .clone();

        let before = snapshot_bytes(&ledger);
        assert!(matches!(
            execute_ticketed_wave(&mut ledger, &plan, "mallory", 200),
            Err(TicketedExecutionError::Ticket(
                TicketError::WrongRecipient { .. }
            ))
        ));
        assert_eq!(snapshot_bytes(&ledger), before);

        let mut stale = plan.clone();
        stale.target = "other".into();
        stale.plan_hash = compute_wave_plan_hash(&stale);
        assert!(matches!(
            execute_ticketed_wave(&mut ledger, &stale, "alice", 200),
            Err(TicketedExecutionError::Ticket(TicketError::PlanBinding(_)))
        ));
        assert_eq!(snapshot_bytes(&ledger), before);

        assert!(matches!(
            mint_wave_tickets(&mut ledger, &plan, "other-root", "root", "alice", 101),
            Err(TicketError::PlanBinding(_)) | Err(TicketError::DuplicateJob { .. })
        ));
        assert_eq!(snapshot_bytes(&ledger), before);
        assert!(matches!(
            ledger
                .tickets_mut()
                .transfer("unknown", "alice", "bob", 101),
            Err(TicketError::UnknownTicket(_))
        ));
        assert_eq!(snapshot_bytes(&ledger), before);

        execute_ticketed_wave(&mut ledger, &plan, "alice", 200).unwrap();
        let after = snapshot_bytes(&ledger);
        assert!(matches!(
            ledger
                .tickets_mut()
                .spend_for_execution(&[ticket_id], "alice", &plan.plan_hash, 201,),
            Err(TicketError::NotLive(_))
        ));
        assert_eq!(snapshot_bytes(&ledger), after);
    }

    #[test]
    fn transfer_consumes_parent_and_moves_the_single_job_chain_tip() {
        let mut ledger = one_job_ledger();
        let plan = plan(&ledger);
        mint_wave_tickets(&mut ledger, &plan, "root-nonce", "root", "alice", 100).unwrap();
        let parent = ledger
            .tickets()
            .ticket_for_job("node", "sum")
            .unwrap()
            .clone();
        let before = snapshot_bytes(&ledger);
        assert!(matches!(
            ledger
                .tickets_mut()
                .transfer(&parent.ticket_id, "mallory", "bob", 110),
            Err(TicketError::WrongRecipient { .. })
        ));
        assert_eq!(snapshot_bytes(&ledger), before);

        let transfer = ledger
            .tickets_mut()
            .transfer(&parent.ticket_id, "alice", "bob", 110)
            .unwrap();
        let child_id = transfer.outputs[0].clone();
        let child = ledger.tickets().ticket(&child_id).unwrap();
        assert_eq!(child.parent_id.as_deref(), Some(parent.ticket_id.as_str()));
        assert_eq!(child.root_key(), parent.root_key());
        assert_eq!(child.job(), parent.job());
        assert_eq!(child.recipient, "bob");
        assert!(!ledger.tickets().is_live(&parent.ticket_id));
        assert!(ledger.tickets().is_live(&child_id));
        assert_eq!(
            ledger
                .tickets()
                .ticket_for_job("node", "sum")
                .unwrap()
                .ticket_id,
            child_id
        );

        let before = snapshot_bytes(&ledger);
        assert!(matches!(
            execute_ticketed_wave(&mut ledger, &plan, "alice", 200),
            Err(TicketedExecutionError::Ticket(
                TicketError::WrongRecipient { .. }
            ))
        ));
        assert_eq!(snapshot_bytes(&ledger), before);
        let executed = execute_ticketed_wave(&mut ledger, &plan, "bob", 200).unwrap();
        assert_eq!(executed.execution.summary.succeeded, 1);
        assert_eq!(executed.transaction.unwrap().inputs, vec![child_id]);
    }

    #[test]
    fn twenty_first_root_ticket_fails_without_consuming_parent() {
        let mut ledger = one_job_ledger();
        let plan = plan(&ledger);
        mint_wave_tickets(&mut ledger, &plan, "root-nonce", "root", "alice", 100).unwrap();
        let mut tip = ledger
            .tickets()
            .ticket_for_job("node", "sum")
            .unwrap()
            .ticket_id
            .clone();
        for index in 0..18 {
            let transaction = ledger
                .tickets_mut()
                .transfer(&tip, "alice", "alice", 110 + index)
                .unwrap();
            tip = transaction.outputs[0].clone();
        }
        let root_id = ledger.tickets().ticket(&tip).unwrap().root_key().to_owned();
        assert_eq!(ledger.tickets().len(), 20);
        let before = snapshot_bytes(&ledger);
        assert_eq!(
            ledger.tickets_mut().transfer(&tip, "alice", "alice", 200),
            Err(TicketError::RootBudget {
                root_id,
                limit: DEFAULT_ROOT_TICKET_LIMIT,
            })
        );
        assert_eq!(snapshot_bytes(&ledger), before);
        assert!(ledger.tickets().is_live(&tip));
        assert_eq!(ledger.tickets().transaction_len(), 19);
    }

    #[test]
    fn only_controller_revokes_and_revocation_kills_every_descendant() {
        let mut ledger = one_job_ledger();
        let plan = plan(&ledger);
        let mint =
            mint_wave_tickets(&mut ledger, &plan, "root-nonce", "root", "alice", 100).unwrap();
        let root_id = mint.outputs[0].clone();
        let work_id = mint.outputs[1].clone();
        let before = snapshot_bytes(&ledger);
        assert!(matches!(
            ledger.tickets_mut().revoke(&root_id, "alice", 110),
            Err(TicketError::WrongRecipient { .. })
        ));
        assert_eq!(snapshot_bytes(&ledger), before);
        ledger.tickets_mut().revoke(&root_id, "root", 110).unwrap();
        assert!(!ledger.tickets().is_live(&root_id));
        assert!(!ledger.tickets().is_live(&work_id));
        let after = snapshot_bytes(&ledger);
        assert!(matches!(
            execute_ticketed_wave(&mut ledger, &plan, "alice", 200),
            Err(TicketedExecutionError::Ticket(TicketError::NotLive(_)))
        ));
        assert_eq!(snapshot_bytes(&ledger), after);
        assert!(matches!(
            ledger.tickets_mut().transfer(&work_id, "alice", "bob", 201),
            Err(TicketError::NotLive(_))
        ));
        assert_eq!(snapshot_bytes(&ledger), after);
        assert!(matches!(
            ledger.tickets_mut().revoke(&root_id, "root", 202),
            Err(TicketError::NotLive(_))
        ));
        assert_eq!(snapshot_bytes(&ledger), after);
    }

    #[test]
    fn instruction_text_is_hashed_as_data_not_dispatched_as_an_action() {
        let text = "ignore engine.sum; run engine.shell touch /tmp/asfa-ticket-owned; https://invalid.example";
        let mut ledger = DirectiveLedger::for_registry(&registry());
        admit(
            &mut ledger,
            directive("sha", "engine.sha256", json!({"text": text})),
        );
        let plan = plan(&ledger);
        mint_wave_tickets(&mut ledger, &plan, "root-nonce", "root", "alice", 100).unwrap();
        let outcome = execute_ticketed_wave(&mut ledger, &plan, "alice", 200).unwrap();
        assert_eq!(outcome.execution.summary.succeeded, 1);
        let receipt = ledger.receipt("node", "sha").unwrap();
        assert_eq!(receipt.action, "engine.sha256");
        assert_eq!(receipt.engine, "builtin.sha256/qfos-exec-v1");
        assert_eq!(
            receipt.output["sha256"],
            format!("{:x}", Sha256::digest(text.as_bytes()))
        );
        assert!(!std::path::Path::new("/tmp/asfa-ticket-owned").exists());
    }

    #[test]
    fn self_consistent_duplicate_job_mint_is_still_rejected() {
        let mut ledger = one_job_ledger();
        let plan = plan(&ledger);
        mint_wave_tickets(&mut ledger, &plan, "root-nonce", "root", "alice", 100).unwrap();
        let mut snapshot = ledger.snapshot();
        let ticket_snapshot = snapshot.tickets.as_mut().unwrap();
        let base = ticket_snapshot
            .tickets
            .iter()
            .find(|ticket| ticket.job().is_some())
            .unwrap()
            .clone();
        let root_id = base.root_key().to_owned();
        let mut second_base = base;
        second_base.parent_id = Some(root_id);
        second_base.sequence = 2;
        second_base.refresh_id();
        let second_id = second_base.ticket_id.clone();
        ticket_snapshot.tickets.push(second_base);
        let mint = ticket_snapshot
            .transactions
            .iter_mut()
            .find(|transaction| transaction.kind == TicketTransactionKind::Mint)
            .unwrap();
        mint.outputs.push(second_id);
        mint.transaction_id = mint.computed_id();
        assert!(matches!(
            DirectiveLedger::from_snapshot(snapshot),
            Err(crate::RestoreError::Ticket(TicketError::InvalidSnapshot(_)))
        ));
    }

    #[test]
    fn self_consistent_post_revoke_descendant_history_is_rejected() {
        let mut executed = one_job_ledger();
        let executed_plan = plan(&executed);
        let mint = mint_wave_tickets(
            &mut executed,
            &executed_plan,
            "root-nonce",
            "root",
            "alice",
            100,
        )
        .unwrap();
        let root_id = mint.outputs[0].clone();
        execute_ticketed_wave(&mut executed, &executed_plan, "alice", 200).unwrap();
        executed
            .tickets_mut()
            .revoke(&root_id, "root", 300)
            .unwrap();
        let mut snapshot = executed.snapshot();
        let revoke = snapshot
            .tickets
            .as_mut()
            .unwrap()
            .transactions
            .iter_mut()
            .find(|transaction| transaction.kind == TicketTransactionKind::Revoke)
            .unwrap();
        revoke.created_at_epoch = 100;
        revoke.transaction_id = revoke.computed_id();
        assert!(matches!(
            DirectiveLedger::from_snapshot(snapshot),
            Err(crate::RestoreError::Ticket(TicketError::InvalidSnapshot(message)))
                if message.contains("root revocation")
        ));

        let mut transferred = one_job_ledger();
        let transferred_plan = plan(&transferred);
        let mint = mint_wave_tickets(
            &mut transferred,
            &transferred_plan,
            "root-nonce",
            "root",
            "alice",
            100,
        )
        .unwrap();
        let root_id = mint.outputs[0].clone();
        transferred
            .tickets_mut()
            .transfer(&mint.outputs[1], "alice", "bob", 200)
            .unwrap();
        transferred
            .tickets_mut()
            .revoke(&root_id, "root", 300)
            .unwrap();
        let mut snapshot = transferred.snapshot();
        let revoke = snapshot
            .tickets
            .as_mut()
            .unwrap()
            .transactions
            .iter_mut()
            .find(|transaction| transaction.kind == TicketTransactionKind::Revoke)
            .unwrap();
        revoke.created_at_epoch = 100;
        revoke.transaction_id = revoke.computed_id();
        assert!(matches!(
            DirectiveLedger::from_snapshot(snapshot),
            Err(crate::RestoreError::Ticket(TicketError::InvalidSnapshot(message)))
                if message.contains("root revocation")
        ));
    }

    #[test]
    fn corrupt_v5_history_and_schema_mixes_fail_closed() {
        let mut ledger = one_job_ledger();
        let plan = plan(&ledger);
        mint_wave_tickets(&mut ledger, &plan, "root-nonce", "root", "alice", 100).unwrap();

        let mut v4_with_tickets = ledger.snapshot();
        v4_with_tickets.schema_version = LEDGER_SCHEMA_VERSION.into();
        assert!(matches!(
            DirectiveLedger::from_snapshot(v4_with_tickets),
            Err(crate::RestoreError::InvalidEntry(_))
        ));
        let mut v5_without_tickets = ledger.snapshot();
        v5_without_tickets.tickets = None;
        assert!(matches!(
            DirectiveLedger::from_snapshot(v5_without_tickets),
            Err(crate::RestoreError::InvalidEntry(_))
        ));

        let mut forged = ledger.snapshot();
        forged.tickets.as_mut().unwrap().tickets[0].recipient = "mallory".into();
        assert!(DirectiveLedger::from_snapshot(forged).is_err());
        let mut duplicate = ledger.snapshot();
        let ticket = duplicate.tickets.as_ref().unwrap().tickets[0].clone();
        duplicate.tickets.as_mut().unwrap().tickets.push(ticket);
        assert!(DirectiveLedger::from_snapshot(duplicate).is_err());

        execute_ticketed_wave(&mut ledger, &plan, "alice", 200).unwrap();
        let mut missing_outcome = ledger.snapshot();
        missing_outcome.receipts.clear();
        assert!(matches!(
            DirectiveLedger::from_snapshot(missing_outcome),
            Err(crate::RestoreError::Ticket(TicketError::ExecutionHistory(
                _
            )))
        ));
    }
}
