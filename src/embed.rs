//! Local multilingual embeddings, computed in-process with ONNX Runtime.
//!
//! The model is loaded on a background thread so the server answers
//! immediately; until it is ready, search falls back to full-text only.

use std::{
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock},
};

use anyhow::{Result, anyhow};
use fastembed::{EmbeddingModel, TextEmbedding, TextInitOptions};

use crate::db::Db;

/// The embedding models that can be selected with `LORE_EMBEDDING_MODEL`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Model {
    E5Small,
    E5Base,
    E5Large,
    #[default]
    BgeM3,
}

impl Model {
    pub fn parse(name: &str) -> Option<Self> {
        match name.trim().to_lowercase().as_str() {
            "e5-small" => Some(Self::E5Small),
            "e5-base" => Some(Self::E5Base),
            "e5-large" => Some(Self::E5Large),
            "bge-m3" => Some(Self::BgeM3),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::E5Small => "e5-small",
            Self::E5Base => "e5-base",
            Self::E5Large => "e5-large",
            Self::BgeM3 => "bge-m3",
        }
    }

    fn fastembed(self) -> EmbeddingModel {
        match self {
            Self::E5Small => EmbeddingModel::MultilingualE5Small,
            Self::E5Base => EmbeddingModel::MultilingualE5Base,
            Self::E5Large => EmbeddingModel::MultilingualE5Large,
            Self::BgeM3 => EmbeddingModel::BGEM3,
        }
    }

    /// Query-to-entry cosine similarity below which a semantic match is noise.
    /// E5 scores sit in a narrow high band; BGE-M3 spreads them out.
    pub fn min_similarity(self) -> f32 {
        match self {
            Self::BgeM3 => 0.48,
            _ => 0.80,
        }
    }

    /// Entry-to-entry similarity above which two entries are drawn as linked.
    pub fn link_similarity(self) -> f32 {
        match self {
            Self::BgeM3 => 0.56,
            _ => 0.86,
        }
    }

    /// E5 models are trained with role prefixes; BGE-M3 takes raw text.
    fn prefixes(self) -> (&'static str, &'static str) {
        match self {
            Self::BgeM3 => ("", ""),
            _ => ("query: ", "passage: "),
        }
    }
}

#[derive(Clone, Default)]
pub struct Embedder {
    model: Arc<OnceLock<Mutex<TextEmbedding>>>,
    kind: Model,
}

impl Embedder {
    /// An embedder that never becomes ready (semantic search disabled).
    pub fn disabled() -> Self {
        Self::default()
    }

    /// Loads the model in the background, then embeds entries that lack one.
    pub fn spawn(kind: Model, cache_dir: PathBuf, db: Db) -> Self {
        let embedder = Self {
            kind,
            ..Self::default()
        };
        let handle = embedder.clone();
        std::thread::spawn(move || {
            let options = TextInitOptions::new(kind.fastembed())
                .with_cache_dir(cache_dir)
                .with_show_download_progress(false);
            match TextEmbedding::try_new(options) {
                Ok(model) => {
                    let _ = handle.model.set(Mutex::new(model));
                    tracing::info!(model = kind.name(), "embedding model ready");
                    if let Err(error) = handle.backfill(&db) {
                        tracing::warn!(%error, "embedding backfill failed");
                    }
                }
                Err(error) => {
                    tracing::warn!(%error, "embedding model unavailable; using full-text search only");
                }
            }
        });
        embedder
    }

    pub fn is_ready(&self) -> bool {
        self.model.get().is_some()
    }

    pub fn embed_query(&self, text: &str) -> Result<Option<Vec<f32>>> {
        self.embed(format!("{}{text}", self.kind.prefixes().0))
    }

    pub fn embed_passage(&self, text: &str) -> Result<Option<Vec<f32>>> {
        self.embed(format!("{}{text}", self.kind.prefixes().1))
    }

    /// Embeds every entry, then every file version, without a vector, and
    /// returns how many entries it embedded. Safe to call repeatedly.
    pub fn backfill(&self, db: &Db) -> Result<usize> {
        let mut done = 0;
        loop {
            let batch = db.missing_embeddings(32)?;
            if batch.is_empty() {
                break;
            }
            for entry in batch {
                match self.embed_passage(&entry.embedding_text())? {
                    Some(vector) => db.set_embedding(entry.id, &vector)?,
                    None => return Ok(done),
                }
                done += 1;
            }
        }
        if done > 0 {
            tracing::info!(count = done, "embedded entries");
        }
        let mut files = 0;
        loop {
            let batch = db.files_missing_embeddings(32)?;
            if batch.is_empty() {
                break;
            }
            for file in batch {
                match self.embed_passage(&file.embedding_text())? {
                    Some(vector) => db.set_file_embedding(file.id, &vector)?,
                    None => return Ok(done),
                }
                files += 1;
            }
        }
        if files > 0 {
            tracing::info!(count = files, "embedded files");
        }
        Ok(done)
    }

    fn embed(&self, text: String) -> Result<Option<Vec<f32>>> {
        let Some(model) = self.model.get() else {
            return Ok(None);
        };
        let mut model = model.lock().unwrap_or_else(|e| e.into_inner());
        let mut vectors = model
            .embed(vec![text], None)
            .map_err(|e| anyhow!("embedding failed: {e}"))?;
        let mut vector = vectors
            .pop()
            .ok_or_else(|| anyhow!("no embedding returned"))?;
        let norm = vector.iter().map(|v| v * v).sum::<f32>().sqrt();
        if norm > 0.0 {
            vector.iter_mut().for_each(|v| *v /= norm);
        }
        Ok(Some(vector))
    }
}
