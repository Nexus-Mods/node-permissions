export interface IOptions {
  recursive?: boolean;
}

export type Permission = 'r' | 'w' | 'x' | 'rw' | 'rx' | 'wx' | 'rwx';
export type UserGroup = 'everyone' | 'owner' | 'group' | 'guest' | 'administrator';

/**
 * give a user or group certain access rights to a file or directory
 * @param path path to the file or directory to change access to
 * @param group either a group (one of UserGroup) or a user id as returned by getUserId
 * @param rights the rights to grant (read, write, execute or a combination thereof)
 */
export function allow(path: string, group: UserGroup | string, rights: Permission): Promise<void>;

/**
 * get the user id for the current user in a format that can be used in allow
 */
export function getUserId(): string;
