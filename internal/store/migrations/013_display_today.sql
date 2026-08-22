-- "Overdue" and "due within a week" were decided with current_date, which the
-- database evaluates in the container's zone -- UTC. The display timezone
-- defaults to Asia/Seoul, so between midnight and 09:00 local the service was
-- still working from yesterday's date: a follow-up that ran out at midnight
-- was not yet marked overdue, and a reminder due today was not yet due.
--
-- display_today() answers the same question in the zone the installation
-- displays. It is STABLE, so a query evaluates it once and can still use the
-- indexes on the date columns. An unset or unparseable zone falls back to UTC
-- rather than failing the query it appears in.
CREATE OR REPLACE FUNCTION display_today() RETURNS date
LANGUAGE plpgsql STABLE AS $$
DECLARE zone text;
BEGIN
        SELECT NULLIF(btrim(value_json->>'timezone'), '') INTO zone FROM settings WHERE key = 'general';
        IF zone IS NULL THEN
                RETURN (now() AT TIME ZONE 'UTC')::date;
        END IF;
        RETURN (now() AT TIME ZONE zone)::date;
EXCEPTION WHEN OTHERS THEN
        RETURN (now() AT TIME ZONE 'UTC')::date;
END $$;
