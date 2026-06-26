import { createContext, useContext, useState, type ReactNode } from "react";
import { api, TOKEN_KEY } from "../lib/api";
import type { User, LoginResponse } from "../types/auth";

interface AuthContextValue {
  user: User | null;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

const STORAGE_KEY = "soc_user";

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(() => {
    const stored = sessionStorage.getItem(STORAGE_KEY);
    return stored ? (JSON.parse(stored) as User) : null;
  });

  async function login(username: string, password: string) {
    const { data } = await api.post<LoginResponse>("/api/v1/auth/login", { username, password });
    sessionStorage.setItem(TOKEN_KEY, data.access_token);
    const u: User = { username: data.username, role: data.role };
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(u));
    setUser(u);
  }

  function logout() {
    sessionStorage.removeItem(TOKEN_KEY);
    sessionStorage.removeItem(STORAGE_KEY);
    setUser(null);
  }

  return (
    <AuthContext.Provider value={{ user, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside AuthProvider");
  return ctx;
}
