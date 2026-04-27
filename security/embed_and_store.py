import os
import git
import json

from dotenv import load_dotenv
from langchain_core.documents import Document
from langchain_community.document_loaders.generic import GenericLoader
from langchain_community.document_loaders.parsers import LanguageParser
from langchain_text_splitters import Language, RecursiveCharacterTextSplitter
from langchain_community.vectorstores import FAISS
from langchain_aws import BedrockEmbeddings

# -----------------------------
# Load environment variables
# -----------------------------
load_dotenv()

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

repo_url = "https://github.com/ninjacoder88/masterpassword-open"
local_path = os.path.join(SCRIPT_DIR, "repo")
src_path = os.path.join(local_path, "src")

# eval report path (your provided path)
eval_path = os.path.join(
    local_path,
    "security",
    "findings",
    "eval_2026-04-27_11-31-53.json"
)

# -----------------------------
# Clone or update repo
# -----------------------------
if os.path.isdir(local_path) and os.path.isdir(os.path.join(local_path, ".git")):
    print("Repo exists. Pulling latest...")
    repo = git.Repo(local_path)
    repo.remotes.origin.pull()
else:
    print("Cloning repo...")
    repo = git.Repo.clone_from(repo_url, local_path)
    print(f"Cloned into: {local_path}")

# -----------------------------
# Load SOURCE CODE (only /src)
# -----------------------------
print("\nLoading source code from /src ...")

code_loader = GenericLoader.from_filesystem(
    src_path,
    glob="**/*",
    suffixes=[".cs", ".csproj", ".json", ".md"],
    parser=LanguageParser(language=Language.CSHARP),
    show_progress=True,
)

code_documents = code_loader.load()

# Tag metadata
for doc in code_documents:
    doc.metadata["source_type"] = "codebase"
    doc.metadata["source"] = "src"

print(f"Loaded {len(code_documents)} code documents")

# -----------------------------
# Load EVAL REPORT
# -----------------------------
print("\nLoading eval report...")

if not os.path.exists(eval_path):
    raise FileNotFoundError(f"Eval file not found: {eval_path}")

with open(eval_path, "r", encoding="utf-8") as f:
    eval_data = json.load(f)

eval_document = Document(
    page_content=json.dumps(eval_data, indent=2),
    metadata={
        "source_type": "security_analysis",
        "source": "eval_report",
        "file_path": eval_path,
    },
)

print("Eval report loaded")

# -----------------------------
# Split documents
# -----------------------------
print("\nSplitting documents...")

# Code splitter (language-aware)
code_splitter = RecursiveCharacterTextSplitter.from_language(
    language=Language.CSHARP,
    chunk_size=8000,
    chunk_overlap=100,
)

# Eval splitter (generic text)
eval_splitter = RecursiveCharacterTextSplitter(
    chunk_size=4000,
    chunk_overlap=200,
)

code_chunks = code_splitter.split_documents(code_documents)
eval_chunks = eval_splitter.split_documents([eval_document])

all_chunks = code_chunks + eval_chunks

print(f"Code chunks: {len(code_chunks)}")
print(f"Eval chunks: {len(eval_chunks)}")
print(f"Total chunks: {len(all_chunks)}")

# -----------------------------
# Create FAISS DB
# -----------------------------
print("\nCreating FAISS vector store...")

embeddings = BedrockEmbeddings(
    model_id="amazon.titan-embed-text-v2:0"
)

db_name = "master_password"

db = FAISS.from_documents(all_chunks, embeddings)

save_path = os.path.join(
    SCRIPT_DIR,
    "..",
    "..",
    "vector_databases",
    f"{db_name}.faiss"
)

db.save_local(save_path)

print(f"\nFAISS DB saved at: {save_path}")
print("Done.")