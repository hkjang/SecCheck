-- A period filter ("from 2026-03-05 to 2026-03-31") compared a timestamptz
-- against a date, which PostgreSQL reads as midnight UTC. With the display
-- timezone ahead of UTC, every day in a report started nine hours late: a
-- review created at 00:30 in Seoul was counted on the previous day, and the
-- first nine hours of the first of the month landed in the month before.
--
-- display_day_start() gives the instant a calendar day begins where the
-- installation lives. The same fallback rule as display_today(): an unset or
-- unparseable zone means UTC rather than a failed query.
CREATE OR REPLACE FUNCTION display_day_start(day date) RETURNS timestamptz
LANGUAGE plpgsql STABLE AS $$
DECLARE zone text;
BEGIN
        SELECT NULLIF(btrim(value_json->>'timezone'), '') INTO zone FROM settings WHERE key = 'general';
        IF zone IS NULL THEN
                RETURN day::timestamp AT TIME ZONE 'UTC';
        END IF;
        RETURN day::timestamp AT TIME ZONE zone;
EXCEPTION WHEN OTHERS THEN
        RETURN day::timestamp AT TIME ZONE 'UTC';
END $$;
