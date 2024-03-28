import { Client } from './client'
import { MAJOR_VERSIONS, MINOR_VERSIONS } from './header'

const client = new Client({
  host: '127.0.0.1',
  port: 49,
  secret: null,
  majorVersion: MAJOR_VERSIONS.TAC_PLUS_MAJOR_VER,
  minorVersion: MINOR_VERSIONS.TAC_PLUS_MINOR_VER_DEFAULT,
  logger: Client.DEFAULT_OPTIONS.logger,
})

// client.authenticate2('user3', 'cisco')
client.authorize('user4', 'cisco')
