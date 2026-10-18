

import express from "express";
import pool from "../config/database.js";
import { authenticateToken } from "../middleware/authenticate.js";
import { authorizeRoles } from "../middleware/authorize.js";

const router = express.Router();

const ALL_ACCESS_ROLES = [
  "SYSTEM_ADMIN",
  "LAB_ANNOTATOR",
  "READ_ONLY_VIEWER",
];

// GET /api/papers
// All three authenticated access roles can view papers.
router.get(
  "/",
  authenticateToken,
  authorizeRoles(...ALL_ACCESS_ROLES),
  async (req, res, next) => {
    try {
      const result = await pool.query(
        `SELECT id, title, abstract, authors, arxiv_id,
                uploader_id, uploaded_at, updated_at
         FROM papers
         ORDER BY uploaded_at DESC`
      );

      return res.status(200).json({
        papers: result.rows,
      });
    } catch (error) {
      return next(error);
    }
  }
);

export default router;
