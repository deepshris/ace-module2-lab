/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'
import dns from 'node:dns'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

function isPrivateIPv4 (ip: string): boolean {
  const parts = ip.split('.').map(Number)
  if (parts.length !== 4 || parts.some(isNaN)) return false

  const [p0, p1, p2, p3] = parts

  // 127.0.0.0/8
  if (p0 === 127) return true
  // 10.0.0.0/8
  if (p0 === 10) return true
  // 172.16.0.0/12
  if (p0 === 172 && p1 >= 16 && p1 <= 31) return true
  // 192.168.0.0/16
  if (p0 === 192 && p1 === 168) return true
  // 169.254.0.0/16
  if (p0 === 169 && p1 === 254) return true
  // 0.0.0.0
  if (p0 === 0) return true

  return false
}

function isPrivateIPv6 (ip: string): boolean {
  const cleanIp = ip.toLowerCase().trim()
  if (cleanIp === '::1' || cleanIp === '::') return true
  if (cleanIp.startsWith('fe8') || cleanIp.startsWith('fe9') || cleanIp.startsWith('fea') || cleanIp.startsWith('feb')) return true // fe80::/10
  if (cleanIp.startsWith('fc') || cleanIp.startsWith('fd')) return true // fc00::/7
  if (cleanIp.startsWith('ff')) return true // ff00::/8
  return false
}

async function isSafeUrl (urlString: string): Promise<boolean> {
  try {
    let parsedUrl: URL
    try {
      parsedUrl = new URL(urlString)
    } catch {
      parsedUrl = new URL('http://' + urlString)
    }

    const hostname = parsedUrl.hostname.toLowerCase()

    // Always block AWS metadata endpoints and Google Cloud metadata
    if (hostname === '169.254.169.254' || hostname.includes('metadata.google.internal')) {
      return false
    }

    const isTest = process.env.NODE_ENV === 'test'

    if (!isTest) {
      if (hostname === 'localhost' || hostname === 'localhost.localdomain') {
        return false
      }
    }

    if (isPrivateIPv4(hostname) || isPrivateIPv6(hostname)) {
      if (isTest && (hostname === '127.0.0.1' || hostname === '::1')) {
        return true
      }
      return false
    }

    try {
      const lookupResult = await dns.promises.lookup(parsedUrl.hostname, { all: true })
      for (const res of lookupResult) {
        const ip = res.address
        if (isPrivateIPv4(ip) || isPrivateIPv6(ip)) {
          if (isTest && (ip === '127.0.0.1' || ip === '::1')) {
            continue
          }
          return false
        }
      }
    } catch {
      // If resolution fails, allow fetch to try and fail normally
    }

    return true
  } catch {
    return false
  }
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          if (!await isSafeUrl(url)) {
            throw new Error('SSRF blocked: request to private/local/metadata IP addresses is forbidden')
          }
          const response = await fetch(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
