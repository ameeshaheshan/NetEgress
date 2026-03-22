import os
import json
import logging
import time
from typing import List, Dict, Optional, Any
import chromadb
from chromadb.config import Settings
import google.generativeai as genai
from dotenv import load_dotenv

# Load environment variables from the project's config directory
env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", ".env")
load_dotenv(env_path)

logger = logging.getLogger(__name__)

import chromadb.utils.embedding_functions as ef

class ResourceExhaustedError(Exception):
    """Custom error for API quota limits."""
    pass

class GeminiEmbeddingFunction(ef.EmbeddingFunction):
    """Custom ChromaDB Embedding Function using Google Gemini API."""
    def __init__(self, api_key: str, model_name: str = "models/gemini-embedding-001"):
        self.api_key = api_key
        self.model_name = model_name
        genai.configure(api_key=self.api_key)

    def __call__(self, input):
        # Call Gemini embedding API
        if isinstance(input, str):
            input = [input]
            
        try:
            result = genai.embed_content(
                model=self.model_name,
                content=input,
                task_type="retrieval_document",
                request_options={"timeout": 10}
            )
            return result['embedding']
        except Exception as e:
            # Raise specific error if quota exceeded to trigger fallback in the manager
            err_msg = str(e).lower()
            if "429" in err_msg or "quota" in err_msg or "exhausted" in err_msg:
                raise ResourceExhaustedError(f"Gemini API Quota Exceeded: {e}")
            raise e

class SimpleKeywordEmbeddingFunction(ef.EmbeddingFunction):
    """Fallback Embedding Function using basic Token Frequency (TF)."""
    def __call__(self, input):
        # Simple TF vectorization for common security terms
        common_terms = ["ssrf", "aws", "metadata", "imds", "internal", "proxy", "request", "forgery", "leak", "cloud", "root", "etc", "passwd", "localhost"]
        embeddings = []
        for text in input:
            tokens = str(text).lower().split()
            vector = [tokens.count(term) for term in common_terms]
            # Pad to 128 for consistency
            vector += [0] * (128 - len(vector)) 
            embeddings.append(vector)
        return embeddings

class SSRFKnowledgeManager:
    """Resilient Hybrid RAG Engine with Automatic Quota Fallback."""
    
    def __init__(self, db_path: str = "knowledge_base/chroma_db", api_key: Optional[str] = None):
        self.db_path = db_path
        self.api_key = api_key or os.environ.get("GOOGLE_API_KEY")
        
        # Cooldown state for Resiliency
        self.cloud_available = True
        self.last_quota_error = 0
        self.cooldown_period = 300 # 5 minutes before retrying Cloud
        
        # Initialize client
        self.client = chromadb.PersistentClient(path=self.db_path)
        
        # 1. Initialize Local/Keyword Collection (Always available)
        self.local_ef = SimpleKeywordEmbeddingFunction()
        self.local_col = self.client.get_or_create_collection(
            name="ssrf_knowledge_local",
            embedding_function=self.local_ef,
            metadata={"description": "Local resilient keyword search"}
        )
        
        # 2. Initialize Cloud/Gemini Collection (If API key exists)
        self.cloud_col = None
        self.cloud_ef = None
        if self.api_key:
            try:
                self.cloud_ef = GeminiEmbeddingFunction(api_key=self.api_key)
                self.cloud_col = self.client.get_or_create_collection(
                    name="ssrf_knowledge_cloud",
                    embedding_function=self.cloud_ef,
                    metadata={"description": "Cloud-powered vector search"}
                )
                logger.info("RAG Engine: Cloud/Gemini mode initialized.")
            except Exception as e:
                logger.warning(f"RAG Engine: Initial Gemini failure: {e}. Falling back to Local Mode.")
                self.cloud_available = False
        else:
            self.cloud_available = False
            logger.info("RAG Engine: No API key found. Defaulting to Local Mode.")

        # Legacy pointer (prefers cloud if available)
        self.collection = self.cloud_col if (self.cloud_col and self.cloud_available) else self.local_col
        
        # Initialize Gemini Generative Model (for analysis)
        if self.api_key:
            genai.configure(api_key=self.api_key)
            self.model = genai.GenerativeModel('gemini-1.5-flash')
        
        # Sync Datasets & Payloads to both "Brains"
        self._sync_all_knowledge()

    def _sync_all_knowledge(self):
        """Populate both cloud and local databases."""
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        
        dataset_path = os.path.join(project_root, "knowledge_base", "ssrf_rag_dataset.json")
        if os.path.exists(dataset_path):
            if self.local_col.count() == 0 or (self.cloud_col and self.cloud_col.count() == 0):
                self.ingest_dataset(dataset_path)
        
        payloads_dir = os.path.join(project_root, "payloads")
        if os.path.exists(payloads_dir):
            self.ingest_payloads(payloads_dir)

    def _check_recovery(self):
        """Check if we can try switching back to Cloud mode."""
        if not self.cloud_available and self.api_key:
            if time.time() - self.last_quota_error > self.cooldown_period:
                logger.info("RAG Engine: Cooldown ended. Attempting to restore Cloud connectivity...")
                self.cloud_available = True
        return self.cloud_available

    def ingest_payloads(self, payloads_dir: str):
        """Batch ingest research payloads into all active brains."""
        ids, docs, metas = [], [], []
        for root, _, files in os.walk(payloads_dir):
            for file in files:
                if file.endswith((".txt", ".py", ".sh")):
                    try:
                        fpath = os.path.join(root, file)
                        with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read().strip()
                        if content:
                            ids.append(f"payload_{file}")
                            docs.append(content)
                            metas.append({"source": "Local Research", "technique": file.split('.')[0], "title": f"Payload: {file}"})
                    except: continue
        
        if not ids: return

        # Sync Local
        self.local_col.upsert(ids=ids, documents=docs, metadatas=metas)
        # Sync Cloud
        if self.cloud_col:
            try:
                self.cloud_col.upsert(ids=ids, documents=docs, metadatas=metas)
            except Exception as e:
                if "429" in str(e) or "quota" in str(e).lower():
                    self.cloud_available = False
                    self.last_quota_error = time.time()

    def ingest_dataset(self, json_path: str):
        """Sync the primary knowledge base."""
        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            ids, docs, metas = [], [], []
            for i, entry in enumerate(data):
                ids.append(entry.get('id', f"doc_{i}"))
                docs.append(entry.get('content', ''))
                metas.append({"source": entry.get('source'), "title": entry.get('title'), "technique": entry.get('technique')})
            
            self.local_col.upsert(ids=ids, documents=docs, metadatas=metas)
            if self.cloud_col:
                self.cloud_col.upsert(ids=ids, documents=docs, metadatas=metas)
            logger.info(f"RAG Engine: Synced {len(ids)} knowledge items.")
        except Exception as e:
            logger.error(f"Sync failed: {e}")

    def retrieve_context(self, query: str, n_results: int = 3) -> List[Dict]:
        """Query with automatic dynamic failover."""
        # Try Cloud first if available
        if self.cloud_col and self._check_recovery():
            try:
                results = self.cloud_col.query(query_texts=[query], n_results=n_results)
                return self._format_results(results)
            except Exception as e:
                err_msg = str(e).lower()
                if "429" in err_msg or "quota" in err_msg or isinstance(e, ResourceExhaustedError):
                    logger.warning("RAG Engine: [QUOTA EXCEEDED] Switching to Local/Resilient mode.")
                    self.cloud_available = False
                    self.last_quota_error = time.time()
                else:
                    logger.error(f"Cloud query error: {e}")

        # Fallback to Local
        results = self.local_col.query(query_texts=[query], n_results=n_results)
        return self._format_results(results)

    def detect_match(self, response_text: str, threshold: float = 0.5) -> Optional[Dict]:
        """RAG-Enhanced Detection with resilience."""
        if not response_text: return None
        sample = str(response_text)[:2000]
        
        hits = self.retrieve_context(sample, n_results=1)
        if hits:
            hit = hits[0]
            # Keyword/Local mode has different distance scaling than Cloud embeddings
            effective_threshold = threshold if self.cloud_available else 0.8
            if hit['distance'] < effective_threshold:
                return {
                    "type": hit['metadata'].get('technique', 'Smart Detection'),
                    "confidence": 1.0 - hit['distance'],
                    "source": hit['metadata'].get('source', 'RAG Intelligence'),
                    "match_title": hit['metadata'].get('title', 'Unknown Pattern'),
                    "resilient_mode": "Cloud" if self.cloud_available else "Local Fallback"
                }
        return None

    def _format_results(self, results):
        hits = []
        if results['documents'] and results['documents'][0]:
            for i in range(len(results['documents'][0])):
                hits.append({
                    "content": results['documents'][0][i],
                    "metadata": results['metadatas'][0][i],
                    "distance": results['distances'][0][i] if 'distances' in results else 0
                })
        return hits

    def analyze_vulnerability(self, log_entry: str, context: List[Dict]) -> str:
        """Expert LLM analysis with fallback status."""
        if not self.api_key or not self._check_recovery():
            return "Resilient Mode: Expert AI analysis unavailable (Local lookup only)."

        ctx_str = "\n\n".join([f"Source: {h['metadata']['title']}\n{h['content']}" for h in context])
        prompt = f"Expert SSRF AI. Analyze findings against context:\nContext:\n{ctx_str}\n\nFinding: {log_entry}"
        
        try:
            return self.model.generate_content(prompt).text
        except Exception as e:
            if "429" in str(e):
                self.cloud_available = False
                self.last_quota_error = time.time()
            return f"Analysis paused: {e}"

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    mgr = SSRFKnowledgeManager()
    print("Resilient RAG initialized.")
