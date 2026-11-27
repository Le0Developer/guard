-- name: ActiveGroupNamesForUser :many
SELECT g.name FROM groups g
JOIN group_members m ON m.group_id=g.id
WHERE m.user_id=sqlc.arg(user_id) AND g.deleted_at IS NULL
ORDER BY g.name;
