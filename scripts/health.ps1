Param(
  [string]$QdrantUrl = $env:QDRANT_URL, 
  [string]$Collection = $env:QDRANT_COLLECTION_NAME,
  [string]$EmbeddingModel = $env:EMBEDDING_MODEL,
  [int]$VectorSize = [int]($env:VECTOR_SIZE)
)

Write-Host "=== Cortex Memory Backend Health ==="

if (-not $QdrantUrl) { $QdrantUrl = 'http://localhost:6333' }
if (-not $Collection) { $Collection = 'cortex-memory' }
if (-not $EmbeddingModel) { $EmbeddingModel = 'text-embedding-3-small' }
if (-not $VectorSize) { $VectorSize = 1536 }

# Ensure OPENAI_API_KEY is populated from User env if missing in Process
if (-not $env:OPENAI_API_KEY -or $env:OPENAI_API_KEY.Length -eq 0) {
  try {
    $userKey = [System.Environment]::GetEnvironmentVariable('OPENAI_API_KEY','User')
    if ($userKey) { $env:OPENAI_API_KEY = $userKey }
  } catch {}
}

Write-Host "Qdrant URL:`t`t$QdrantUrl"
Write-Host "Collection:`t`t$Collection"
Write-Host "Embedding Model:`t$EmbeddingModel"
Write-Host "Vector Size:`t`t$VectorSize"

function Test-Qdrant {
  try {
    $root = Invoke-WebRequest -UseBasicParsing "$QdrantUrl/" -TimeoutSec 3
    if ($root.StatusCode -ne 200) { throw "Qdrant root status $($root.StatusCode)" }
    $collections = (Invoke-WebRequest -UseBasicParsing "$QdrantUrl/collections").Content | ConvertFrom-Json
    $names = $collections.result.collections.name
    Write-Host "Qdrant OK. Collections: $(($names -join ', '))"
    $detail = (Invoke-WebRequest -UseBasicParsing "$QdrantUrl/collections/$Collection").Content | ConvertFrom-Json
    $size = $detail.result.config.params.vectors.size
    $distance = $detail.result.config.params.vectors.distance
    if ($size -ne $VectorSize) {
      Write-Error "Vector size mismatch: expected $VectorSize, actual $size"
      return $false
    }
    Write-Host "Collection OK. size=$size distance=$distance"
    return $true
  } catch {
    Write-Error "Qdrant check failed: $_"
    return $false
  }
}

function Test-OpenAIEmbedding {
  if (-not $env:OPENAI_API_KEY) {
    Write-Warning "OPENAI_API_KEY not set; skipping embedding test"
    return $null
  }
  try {
    $body = @{ model = $EmbeddingModel; input = 'backend health probe' } | ConvertTo-Json
    $resp = Invoke-RestMethod -Method Post -Uri "https://api.openai.com/v1/embeddings" -Headers @{ Authorization = "Bearer $($env:OPENAI_API_KEY)"; 'Content-Type' = 'application/json' } -Body $body
    $dim = $resp.data[0].embedding.Count
    if ($dim -ne $VectorSize) {
      Write-Error "Embedding dim mismatch: expected $VectorSize, got $dim (model=$EmbeddingModel)"
      return $false
    }
    Write-Host "OpenAI embeddings OK. dim=$dim"
    return $true
  } catch {
    Write-Error "OpenAI embedding test failed: $_"
    return $false
  }
}

$qok = Test-Qdrant
$eok = Test-OpenAIEmbedding

if ($qok -and ($eok -ne $false)) {
  Write-Host "Backend health: PASS"
  exit 0
} else {
  Write-Error "Backend health: FAIL"
  exit 1
}
