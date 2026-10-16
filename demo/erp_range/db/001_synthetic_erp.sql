-- MON Cyber Range — generated fictional student identities ONLY.
CREATE TABLE IF NOT EXISTS synthetic_students (
    student_code text PRIMARY KEY CHECK (student_code LIKE 'DEMO-%'),
    display_name text NOT NULL,
    programme text NOT NULL
);
INSERT INTO synthetic_students(student_code, display_name, programme)
SELECT
    'DEMO-' || lpad(seq::text, 5, '0'),
    'Fictional Student ' || lpad(seq::text, 5, '0'),
    CASE WHEN seq % 3 = 0 THEN 'Engineering Practice'
         WHEN seq % 3 = 1 THEN 'Computer Fundamentals'
         ELSE 'Digital Systems'
    END
FROM generate_series(1, 250) AS seq
ON CONFLICT (student_code) DO NOTHING;
