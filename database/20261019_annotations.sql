
-- Research paper annotations
-- Supports positional highlights and comments on PDF pages.

CREATE TABLE IF NOT EXISTS annotations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    paper_id UUID NOT NULL
        REFERENCES papers(id) ON DELETE CASCADE,

    created_by UUID NOT NULL
        REFERENCES users(id) ON DELETE RESTRICT,

    page_number INTEGER NOT NULL CHECK (page_number >= 1),

    content TEXT NOT NULL
        CHECK (TRIM(content) <> ''),

    -- Optional normalized coordinates for a highlighted region.
    position_x NUMERIC(6, 5)
        CHECK (position_x >= 0 AND position_x <= 1),

    position_y NUMERIC(6, 5)
        CHECK (position_y >= 0 AND position_y <= 1),

    region_width NUMERIC(6, 5)
        CHECK (region_width > 0 AND region_width <= 1),

    region_height NUMERIC(6, 5)
        CHECK (region_height > 0 AND region_height <= 1),

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_annotations_paper_id
    ON annotations (paper_id);

CREATE INDEX IF NOT EXISTS idx_annotations_created_by
    ON annotations (created_by);
