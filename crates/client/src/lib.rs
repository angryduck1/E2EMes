//! E2EMes client library: the network connection, local message store and the
//! [`Messenger`] that ties them to the user's identity key. The `e2emes` binary
//! is a console UI on top of it.

pub mod connection;
pub mod messenger;
pub mod store;
pub mod vault;

pub use connection::{connect, Connection, RequestError};
pub use messenger::{Decrypted, Messenger, MessengerError, Notice};
pub use store::Store;
pub use vault::AccountVault;
