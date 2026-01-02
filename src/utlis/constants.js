// Defines all possible user roles in the system
export const userRolesEnum = {
  ADMIN: "admin",              // Full system access
  PROJECT_ADMIN: "project_admin", // Manages a specific project
  MEMEBER: "member"            // Regular project member
};

// Array of all available user roles (useful for validation)
export const AvailableUserRole = Object.values(userRolesEnum);

// Defines all possible task statuses
export const TaskStatusEnum = {
  TODO: "todo",                // Task not started yet
  IN_PROGRESS: "in_progress",  // Task currently being worked on
  DONE: "done"                 // Task completed
};

// Array of all available task statuses (useful for validation)
export const AvailableTaskStatus = Object.values(TaskStatusEnum);
