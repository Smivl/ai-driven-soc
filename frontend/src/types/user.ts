export interface SocUser {
  id: number;
  username: string;
  email: string | null;
  role: string;
  is_active: boolean;
  created_at: string | null;
}
