"use client";

import { useEffect, useState } from "react";

interface Issue {
  id: number;
  title: string;
  status: string;
  priority: string;
  user_id: number;
  reporter_name: string;
}

interface UserProfile {
  id: number;
  name: string;
  email: string;
  role: string;
  total_bugs_reported: number;
  open_bugs_count: number;
}

const API_URL = process.env.NEXT_PUBLIC_RUST_API_URL || "http://127.0.0.1:4000/api";

export default function IssuesDashboard() {
  const [token, setToken] = useState<string | null>(null);
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [issues, setIssues] = useState<Issue[]>([]);
  const [filterMyBugs, setFilterMyBugs] = useState(false);

  // Auth form states
  const [isRegistering, setIsRegistering] = useState(false);
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("Full-Stack Developer");
  const [authError, setAuthError] = useState("");

  // Issue form states
  const [title, setTitle] = useState("");
  const [priority, setPriority] = useState("Medium");
  const [loading, setLoading] = useState(true);

  const fetchIssues = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_URL}/issues`, { cache: "no-store" });
      if (res.ok) {
        setIssues(await res.json());
      }
    } catch (err) {
      console.error("Cannot reach Rust API at", API_URL, err);
      setAuthError(`Cannot connect to Rust API at ${API_URL}. Make sure 'cargo run' is active on port 4000.`);
    } finally {
      setLoading(false);
    }
  };

  const fetchProfile = async (jwt: string) => {
    try {
      const res = await fetch(`${API_URL}/profile`, {
        headers: { Authorization: `Bearer ${jwt}` },
        cache: "no-store",
      });
      if (res.ok) {
        setProfile(await res.json());
      } else {
        handleLogout();
      }
    } catch (err) {
      console.error("Failed to fetch profile:", err);
    }
  };

  useEffect(() => {
    const savedToken = localStorage.getItem("devtrack_token");
    if (savedToken) {
      setToken(savedToken);
      fetchProfile(savedToken);
    }
    fetchIssues();
  }, []);

  const handleAuthSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError("");

    const endpoint = isRegistering ? "register" : "login";

    const body = isRegistering ? { name, email, password, role } : { email, password };

    try {
      console.log("Frontend origin:", window.location.origin);
      console.log("Calling Rust API:", `${API_URL}/auth/${endpoint}`);

      const res = await fetch(`${API_URL}/auth/${endpoint}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(body),
      });

      const responseText = await res.text();

      let data: any = {};

      try {
        data = responseText ? JSON.parse(responseText) : {};
      } catch {
        data = {};
      }

      if (!res.ok) {
        setAuthError(typeof data === "string" ? data : responseText || `Request failed: ${res.status}`);
        return;
      }

      if (!data.token || !data.user) {
        setAuthError("Invalid response received from Rust authentication API.");
        return;
      }

      localStorage.setItem("devtrack_token", data.token);

      setToken(data.token);
      setProfile(data.user);
      setEmail("");
      setPassword("");
    } catch (error) {
      console.error("Authentication network error:", error);

      setAuthError(`Unable to connect to Rust API at ${API_URL}/auth/${endpoint}. Check backend availability and CORS configuration.`);
    }
  };
  const handleLogout = () => {
    localStorage.removeItem("devtrack_token");
    setToken(null);
    setProfile(null);
    setFilterMyBugs(false);
  };

  const handleCreateIssue = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!title.trim() || !token) return;

    const res = await fetch(`${API_URL}/issues`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ title, priority }),
    });

    if (res.ok) {
      setTitle("");
      await fetchIssues();
      await fetchProfile(token);
    }
  };

  const handleStatusToggle = async (issue: Issue) => {
    if (!token) return;
    const nextStatus = issue.status === "Open" ? "Closed" : "Open";

    await fetch(`${API_URL}/issues/${issue.id}`, {
      method: "PATCH",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ status: nextStatus }),
    });
    await fetchIssues();
    await fetchProfile(token);
  };

  const handleDelete = async (id: number) => {
    if (!token) return;
    await fetch(`${API_URL}/issues/${id}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${token}` },
    });
    await fetchIssues();
    await fetchProfile(token);
  };

  const displayedIssues = filterMyBugs && profile ? issues.filter((i) => i.user_id === profile.id) : issues;

  return (
    <main className="max-w-4xl mx-auto p-8 space-y-8">
      <header className="flex items-center justify-between border-b pb-4">
        <h1 className="text-2xl font-bold">DevTrack (Rust + MSSQL + Next.js)</h1>
        {profile && (
          <button onClick={handleLogout} className="text-sm px-3 py-1.5 rounded border hover:bg-gray-100 dark:hover:bg-gray-800">
            Logout
          </button>
        )}
      </header>

      {/* Profile Section OR Login/Register Form */}
      {profile ? (
        <section className="border rounded-lg p-6 bg-slate-50 dark:bg-slate-900 flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
          <div>
            <span className="text-xs font-semibold uppercase tracking-wider text-blue-600">{profile.role}</span>
            <h2 className="text-xl font-bold mt-1">{profile.name}</h2>
            <p className="text-sm text-gray-500">{profile.email}</p>
          </div>

          <div className="flex gap-4">
            <div className="border rounded px-4 py-2 text-center bg-white dark:bg-slate-800">
              <p className="text-2xl font-bold">{profile.total_bugs_reported}</p>
              <p className="text-xs text-gray-500">Bugs Reported</p>
            </div>
            <div className="border rounded px-4 py-2 text-center bg-white dark:bg-slate-800">
              <p className="text-2xl font-bold text-amber-600">{profile.open_bugs_count}</p>
              <p className="text-xs text-gray-500">Open Bugs</p>
            </div>
          </div>
        </section>
      ) : (
        <section className="border rounded-lg p-6 max-w-md mx-auto space-y-4">
          <h2 className="text-lg font-bold">{isRegistering ? "Create Developer Account" : "Sign In to Add Bugs"}</h2>

          {authError && <p className="text-sm text-red-600 bg-red-50 p-2 rounded">{authError}</p>}

          <form onSubmit={handleAuthSubmit} className="space-y-3">
            {isRegistering && (
              <>
                <input type="text" placeholder="Full Name" value={name} onChange={(e) => setName(e.target.value)} required className="w-full border rounded px-3 py-2 text-black" />
                <input
                  type="text"
                  placeholder="Role (e.g. Team Lead, Backend Dev)"
                  value={role}
                  onChange={(e) => setRole(e.target.value)}
                  className="w-full border rounded px-3 py-2 text-black"
                />
              </>
            )}
            <input
              type="email"
              placeholder="Email Address"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              className="w-full border rounded px-3 py-2 text-black"
            />
            <input
              type="password"
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              className="w-full border rounded px-3 py-2 text-black"
            />
            <button type="submit" className="w-full bg-blue-600 text-white py-2 rounded font-medium">
              {isRegistering ? "Register & Login" : "Login"}
            </button>
          </form>

          <button onClick={() => setIsRegistering(!isRegistering)} className="text-sm text-blue-600 underline w-full text-center">
            {isRegistering ? "Already have an account? Sign in" : "Need an account? Register here"}
          </button>
        </section>
      )}

      {/* Protected Add Bug Form */}
      {profile && (
        <form onSubmit={handleCreateIssue} className="flex gap-3">
          <input
            type="text"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder="Report a new bug or issue..."
            className="flex-1 border rounded px-3 py-2 text-black"
          />
          <select value={priority} onChange={(e) => setPriority(e.target.value)} className="border rounded px-3 py-2 text-black">
            <option value="Low">Low</option>
            <option value="Medium">Medium</option>
            <option value="High">High</option>
          </select>
          <button type="submit" className="bg-blue-600 text-white px-5 py-2 rounded font-medium">
            Add Bug
          </button>
        </form>
      )}

      {/* Issue List & Filter */}
      <section className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold">Reported Bugs</h2>
          {profile && (
            <button onClick={() => setFilterMyBugs(!filterMyBugs)} className={`text-sm px-3 py-1 rounded border ${filterMyBugs ? "bg-blue-600 text-white" : ""}`}>
              {filterMyBugs ? "Showing My Bugs Only" : "Filter: My Bugs"}
            </button>
          )}
        </div>

        {loading ? (
          <p>Loading issues from Rust API...</p>
        ) : (
          <ul className="space-y-3">
            {displayedIssues.map((issue) => (
              <li key={issue.id} className="flex items-center justify-between border rounded p-4">
                <div>
                  <p className="font-semibold">{issue.title}</p>
                  <span className="text-sm text-gray-500">
                    Reported by: <strong>{issue.reporter_name}</strong> | Priority: {issue.priority} | Status: {issue.status}
                  </span>
                </div>

                {profile && (
                  <div className="flex gap-2">
                    <button onClick={() => handleStatusToggle(issue)} className="px-3 py-1 border rounded text-sm">
                      Mark {issue.status === "Open" ? "Closed" : "Open"}
                    </button>
                    <button onClick={() => handleDelete(issue.id)} className="px-3 py-1 bg-red-600 text-white rounded text-sm">
                      Delete
                    </button>
                  </div>
                )}
              </li>
            ))}
          </ul>
        )}
      </section>
    </main>
  );
}
