// The agent's own database role (IMPLEMENTATION 3.9 "Think": "its own key store and its own database role"). The role
// can use its own tables, mark nonces used, and read the enrollment keys it checks requests against. It cannot read
// deals, evidence, signatures or the relay's queue, so a flaw in the agent does not open the coordinator's data.
// Source: https://www.postgresql.org/docs/current/sql-grant.html
export const agentRoleSql = (role: string, password: string): string[] => {
  const ident = `"${role.replace(/"/g, '""')}"`;
  return [
    `CREATE ROLE ${ident} LOGIN PASSWORD '${password.replace(/'/g, "''")}' NOSUPERUSER NOCREATEDB NOCREATEROLE`,
    `GRANT SELECT, INSERT, UPDATE ON recovery_agent_share, recovery_agent_recovery, recovery_agent_refresh TO ${ident}`,
    `GRANT SELECT, INSERT ON frost_nonce_use TO ${ident}`,
    `GRANT SELECT ON enrollment_key TO ${ident}`,
  ];
};
