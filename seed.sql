.mode column

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  role TEXT CHECK(role IN ('candidate', 'recruiter', 'admin')) NOT NULL DEFAULT 'candidate',
  hash TEXT NOT NULL,
  first_name TEXT NOT NULL,
  last_name TEXT NOT NULL,
  is_verified INTEGER CHECK(is_verified IN (0, 1)) NOT NULL DEFAULT 0,
  password_reset_token TEXT,
  created_at TEXT DEFAULT (datetime('now','localtime')),
  updated_at TEXT DEFAULT (datetime('now','localtime'))  
);


CREATE TABLE IF NOT EXISTS jobs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  company TEXT NOT NULL,
  image TEXT NOT NULL default 'https://placehold.co/600x400.png',
  tags TEXT NOT NULL,
  url TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now','localtime')),
  updated_at TEXT DEFAULT (datetime('now','localtime')),  
  creator_id INTEGER NOT NULL,
  FOREIGN KEY(creator_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS favorites (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  job_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  FOREIGN KEY(job_id) REFERENCES jobs(id),
  FOREIGN KEY(user_id) REFERENCES users(id)
);

-- Insert 1 user
INSERT INTO users (email, role, hash, first_name, last_name, is_verified) VALUES
  ('user@mail.com', 'recruiter', '$2b$10$0sUfYdE4M4gQJw3cS6w6IeYv', 'John', 'Doe', 1);


-- Insert 3 jobs
INSERT INTO jobs (title, description, company, image, tags, url, creator_id) VALUES
('Software Engineer', 'We are looking for a software engineer to join our team', 'Foundation', 'https://placehold.co/600x400.png', 'software, engineer, fullstack, developer, javascript',  'https://www.google.com', 1), 
('Data Analyst', 'We are looking for a data analyst to join our team', 'Foundation', 'https://placehold.co/600x400.png', 'data, analyst, fullstack', 'https://www.google.com', 1),
('Product Manager', 'We are looking for a product manager to join our team', 'Foundation', 'https://placehold.co/600x400.png', 'product, manager, fullstack', 'https://www.google.com', 1);