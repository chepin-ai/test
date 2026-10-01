//! 系统调用层

pub struct SyscallTable;

impl SyscallTable {
    pub const fn new() -> Self {
        Self
    }
}

pub enum Syscall {
    HyperBind,
    OperadCompose,
    HippocampalEncode,
    SmallWorldNavigate,
    ZKAttest,
    EnclaveEnter,
}
