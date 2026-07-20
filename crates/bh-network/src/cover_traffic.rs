//! Constant-interval dummy traffic between client and entry node, so sending
//! a real message is indistinguishable from being idle. Configurable given
//! the battery/data cost. See `docs/SPEC.md` §5.2.

use crate::NetworkError;

pub struct CoverTrafficGenerator {
    pub enabled: bool,
}

impl CoverTrafficGenerator {
    pub fn start(&self) -> Result<(), NetworkError> {
        todo!("wire up constant-interval dummy traffic — see docs/SPEC.md §5.2")
    }
}
