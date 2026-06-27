import os
import nltk
import torch
import numpy as np
from sklearn.metrics.pairwise import cosine_similarity
from sentence_transformers import SentenceTransformer

# Path to your local fine-tuned model
_DEFAULT_MODEL_DIR = os.path.join(
    os.path.dirname(__file__), 
    "content", 
    "sts_finetuned_miniLM"
)

_MODEL_CACHE = None


def _ensure_nltk():
    """Download required NLTK tokenizers."""
    try: nltk.download("punkt", quiet=True)
    except Exception: pass
    try: nltk.download("punkt_tab", quiet=True)
    except Exception: pass


def load_model(model_path=None):
    """Load and cache the fine-tuned sentence transformer."""
    global _MODEL_CACHE

    if model_path is None:
        model_path = _DEFAULT_MODEL_DIR

    if _MODEL_CACHE is not None:
        return _MODEL_CACHE

    if not os.path.isdir(model_path):
        raise FileNotFoundError(
            f"Model directory does not exist: {model_path}
"
            f"Expected model at: {_DEFAULT_MODEL_DIR}"
        )

    device = "cuda" if torch.cuda.is_available() else "cpu"
    model = SentenceTransformer(model_path)
    model = model.to(device)
    _MODEL_CACHE = model
    return model


def group_paragraph_graph_adjacent(
    paragraph: str,
    model=None,
    global_threshold=0.35,
    adjacent_threshold=0.15
):
    """
    Segment a paragraph into context groups using:
    - pairwise cosine similarity (global graph edges)
    - adjacency similarity (neighbor sentences)
    """
    _ensure_nltk()

    sentences = nltk.sent_tokenize(paragraph)
    if len(sentences) == 0:
        return {"sentences": [], "contexts": []}

    if model is None:
        model = load_model()

    embeddings = model.encode(sentences, convert_to_numpy=True)
    sim_matrix = cosine_similarity(embeddings)

    n = len(sentences)
    adj = [[] for _ in range(n)]

    # Build graph edges
    for i in range(n):
        for j in range(i + 1, n):
            sim = float(sim_matrix[i][j])
            add_edge = False

            # Global threshold
            if sim >= global_threshold:
                add_edge = True

            # Adjacent sentences relax threshold
            elif abs(i - j) == 1 and sim >= adjacent_threshold:
                add_edge = True

            if add_edge:
                adj[i].append(j)
                adj[j].append(i)

    # Extract connected components
    visited = [False] * n
    components = []

    for i in range(n):
        if not visited[i]:
            stack = [i]
            comp = []
            visited[i] = True

            while stack:
                node = stack.pop()
                comp.append(node)
                for nxt in adj[node]:
                    if not visited[nxt]:
                        visited[nxt] = True
                        stack.append(nxt)

            components.append(sorted(comp))

    # Prepare return structure
    results = []
    for cid, comp in enumerate(components, start=1):
        results.append({
            "context_id": cid,
            "sentence_indices": comp,
            "sentences": [sentences[k] for k in comp]
        })

    return {
        "sentences": sentences,
        "contexts": results,
        "similarity_matrix": sim_matrix.tolist()
    }