/** 最小 JS 样例 — 用于 LSP definition 冒烟 */

function getUserInput(request) {
  return request.query.name;
}

function buildQuery(name) {
  return "SELECT * FROM users WHERE name = '" + name + "'";
}

function runQuery(query, db) {
  return db.execute(query);
}

function handleRequest(request, db) {
  const name = getUserInput(request);
  const query = buildQuery(name);
  return runQuery(query, db);
}

module.exports = { handleRequest, getUserInput, buildQuery, runQuery };
