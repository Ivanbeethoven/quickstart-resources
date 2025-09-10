"""Query & QA utilities for an existing repo knowledge base.

This module is import-friendly for LangGraph integration.

Expect directory layout produced by build.py:
  root_dir/{repo_name}/rag_embeddings/{index.faiss,index.pkl,meta.jsonl,config.json}

Public functions:
  load_vector_store(root_dir: str|Path, repo_name: str, embedding_model: str) -> FAISS
  vector_search(vs, query: str, k: int) -> list[Document]
  answer_question(vs, query: str, *, rerank: bool = True, rerank_model: str = ..., final_k: int = 6, llm_model: str|None=None) -> dict

CLI (simple):
  python -m opensource_rag.rag --root-dir ./kb --repo cubefs --query "metadata replication" --final-k 6
  python -m opensource_rag.rag --root-dir ./kb --repo cubefs --ask "How does metadata replication work?" --no-rerank
"""
from __future__ import annotations

import argparse, os
from pathlib import Path
from typing import List, Dict

from rich import print
from sentence_transformers import CrossEncoder
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_community.vectorstores import FAISS
from langchain.schema import Document
from llm.base import create_llm_client  # use project LLM client


def load_vector_store(root_dir: str | Path, repo_name: str, embedding_model: str) -> FAISS:
	embed_dir = Path(root_dir) / repo_name / 'rag_embeddings'
	if not (embed_dir / 'index.faiss').exists():
		raise FileNotFoundError(f'Vector index missing: {embed_dir}')
	embeddings = HuggingFaceEmbeddings(model_name=embedding_model, encode_kwargs={'normalize_embeddings': True})
	vs = FAISS.load_local(str(embed_dir), embeddings, allow_dangerous_deserialization=True)
	return vs


def vector_search(vs: FAISS, query: str, k: int = 5) -> List[Document]:
	return vs.similarity_search(query, k=k)


def rerank(query: str, docs: List[Document], model: str, top_k: int) -> List[Document]:
	if not docs:
		return []
	ce = CrossEncoder(model)
	scores = ce.predict([(query, d.page_content) for d in docs])
	ranked = sorted(zip(docs, scores), key=lambda x: x[1], reverse=True)
	return [d for d,_ in ranked[:top_k]]


def build_prompt(query: str, docs: List[Document], max_ctx: int = 6000) -> str:
	agg, used = [], 0
	for d in docs:
		txt = d.page_content.strip()
		if used + len(txt) > max_ctx:
			remain = max_ctx - used
			if remain <= 0:
				break
			txt = txt[:remain]
		meta = d.metadata
		agg.append(f"<doc source='{meta.get('file') or meta.get('source')}' type='{meta.get('type')}'>{txt}</doc>")
		used += len(txt)
	ctx = '\n\n'.join(agg)
	return (
		"You are an English technical assistant. Use ONLY the provided context. "
		"If the answer is not clearly in the context, respond: 'Insufficient information in provided context.'\n\n"
		f"Context:\n{ctx}\n\nQuestion:\n{query}\n\nAnswer in English succinctly with source references:" )


def call_llm(prompt: str, llm_model: str | None):
	"""Use local llm module client; return None on failure (triggers heuristic fallback)."""
	try:
		client = create_llm_client()
	except Exception as e:  # no key or init failure
		print(f"[red]LLM init failed: {e}")
		return None
	try:
		messages = [{"role": "user", "content": prompt}]
		text = client.chat(messages, model=llm_model)
		return text
	except Exception as e:  # pragma: no cover
		print(f"[red]LLM call failed: {e}")
		return None


def answer_question(vs: FAISS, query: str, *, embedding_model: str, rerank_enabled: bool = True,
					rerank_model: str = 'cross-encoder/ms-marco-MiniLM-L-6-v2', search_k: int = 25,
					final_k: int = 6, llm_model: str | None = None, max_ctx: int = 6000,
					repo_name: str | None = None) -> Dict:
	docs = vector_search(vs, query, k=search_k)
	if rerank_enabled:
		docs = rerank(query, docs, rerank_model, top_k=final_k)
	else:
		docs = docs[:final_k]
	prompt = build_prompt(query, docs, max_ctx=max_ctx)
	answer = call_llm(prompt, llm_model)
	if not answer:
		raise RuntimeError("LLM call failed or unavailable (no fallback). Set API key or check llm module.")
	return { 'answer': answer, 'contexts': [d.metadata for d in docs] }


# -------- CLI (light) --------
def main():  # pragma: no cover
	parser = argparse.ArgumentParser(description='Query existing repo knowledge base')
	parser.add_argument('--root-dir', default='./kb')
	parser.add_argument('--repo', required=True, help='Repository folder name under root-dir')
	parser.add_argument('--embedding-model', default='sentence-transformers/all-mpnet-base-v2')
	parser.add_argument('--query', default='', help='Vector search only')
	parser.add_argument('--ask', default='', help='Run QA (English)')
	parser.add_argument('--search-k', type=int, default=25)
	parser.add_argument('--final-k', type=int, default=6)
	parser.add_argument('--no-rerank', action='store_true')
	parser.add_argument('--rerank-model', default='cross-encoder/ms-marco-MiniLM-L-6-v2')
	parser.add_argument('--llm-model', default=None)
	args = parser.parse_args()

	vs = load_vector_store(args.root_dir, args.repo, args.embedding_model)
	if args.query:
		docs = vector_search(vs, args.query, k=args.final_k)
		print(f"[bold cyan]Query:[/bold cyan] {args.query}")
		for i, d in enumerate(docs, 1):
			snippet = d.page_content[:160].replace('\n',' ')
			print(f"[yellow]{i}. file={d.metadata.get('file')} type={d.metadata.get('type')}[/yellow]\n    {snippet}...")
	if args.ask:
		res = answer_question(vs, args.ask, embedding_model=args.embedding_model, rerank_enabled=not args.no_rerank,
							  rerank_model=args.rerank_model, search_k=args.search_k, final_k=args.final_k,
							  llm_model=args.llm_model, repo_name=args.repo)
		print('[bold green]Answer:\n' + (res['answer'] or 'N/A') + '[/bold green]')


if __name__ == '__main__':  # pragma: no cover
	main()

