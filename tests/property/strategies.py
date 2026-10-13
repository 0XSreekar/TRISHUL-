from hypothesis import strategies as st

from trishul.contracts.labels import Label, Level, SourceRef, Tag

sources = st.builds(
    SourceRef,
    kind=st.sampled_from(
        ["user", "system", "tool_result", "document", "web", "email", "voice", "model"]
    ),
    id=st.text(alphabet="abc123", min_size=1, max_size=3),
)
labels = st.builds(
    Label,
    level=st.sampled_from(list(Level)),
    sources=st.frozensets(sources, max_size=4),
    tags=st.frozensets(st.sampled_from(list(Tag)), max_size=4),
)
