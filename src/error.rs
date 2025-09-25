use thiserror::Error;

#[derive(Error, Debug)]
pub enum SecmonError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Inotify error: {0}")]
    Inotify(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Channel error: {0}")]
    Channel(String),
}

