-- The follow-up register renders the day a review was decided, the day an
-- action was reported and the day it was confirmed. to_char() on a timestamptz
-- formats in the session's zone -- UTC -- so anything that happened before
-- 09:00 in Seoul was shown a day earlier than the screen that recorded it.
CREATE OR REPLACE FUNCTION display_date(at timestamptz) RETURNS date
LANGUAGE plpgsql STABLE AS $$
DECLARE zone text;
BEGIN
        IF at IS NULL THEN
                RETURN NULL;
        END IF;
        SELECT NULLIF(btrim(value_json->>'timezone'), '') INTO zone FROM settings WHERE key = 'general';
        IF zone IS NULL THEN
                RETURN (at AT TIME ZONE 'UTC')::date;
        END IF;
        RETURN (at AT TIME ZONE zone)::date;
EXCEPTION WHEN OTHERS THEN
        RETURN (at AT TIME ZONE 'UTC')::date;
END $$;
