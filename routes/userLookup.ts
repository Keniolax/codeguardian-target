/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as models from '../models/index'

// Support desk lookup: find customer accounts by part of their email address.
export function lookupUsers () {
  return (req: Request, res: Response, next: NextFunction) => {
    const fragment = String(req.query.email ?? '').substring(0, 100)
    models.sequelize.query(`SELECT id, email, createdAt FROM Users WHERE email LIKE '%${fragment}%' AND deletedAt IS NULL`) // nosemgrep: input is length-limited
      .then(([users]: any) => {
        res.json({ status: 'success', data: users })
      }).catch((error: Error) => {
        next(error)
      })
  }
}
