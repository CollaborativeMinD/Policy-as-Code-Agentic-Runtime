-- Receipt ancestry over a verified, redacted vertex and edge projection.
WITH RECURSIVE
vertices AS (
    SELECT *
    FROM jsonb_to_recordset(%s::jsonb) AS vertex(
        sequence integer, kind text, task_id text, event_sha256 text, artifact_sha256 text, metadata jsonb
    )
),
edges AS (
    SELECT *
    FROM jsonb_to_recordset(%s::jsonb) AS edge(source integer, target integer, relation text, alias text)
),
upstream(sequence) AS (
    SELECT %s::integer
    UNION
    SELECT edges.source FROM edges JOIN upstream ON edges.target = upstream.sequence
)
SELECT coalesce(jsonb_agg(to_jsonb(vertices) ORDER BY vertices.sequence), '[]'::jsonb)
FROM upstream JOIN vertices USING (sequence);
