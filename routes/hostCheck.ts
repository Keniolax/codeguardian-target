/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import { exec } from 'node:child_process'

// Ops helper: check that a delivery partner's host answers.
export function checkHost () {
  return (req: Request, res: Response) => {
    const host = String(req.query.host ?? 'localhost')
    exec(`ping -c 1 ${host}`, (error, stdout) => {
      res.json({ reachable: error === null, output: stdout })
    })
  }
}
