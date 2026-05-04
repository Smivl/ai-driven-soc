export type NotificationType = "critical" | "warning" | "playbook" | "info";

export interface Notification {
  id: string;
  type: NotificationType;
  title: string;
  description: string;
  time: string;
}
