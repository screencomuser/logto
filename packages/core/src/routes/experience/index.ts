/**
 * @overview This file implements the routes for the user interaction experience (RFC 0004).
 *
 * Note the experience APIs also known as interaction APIs v2,
 * are the new version of the interaction APIs with design improvements.
 *
 * @see {@link https://github.com/logto-io/rfcs | Logto RFCs} for more information about RFC 0004.
 *
 * @remarks
 * The experience APIs can be used by developers to build custom user interaction experiences.
 */

import { identificationApiPayloadGuard } from '@logto/schemas';
import type Router from 'koa-router';

import RequestError from '#src/errors/RequestError/index.js';
import koaAuditLog from '#src/middleware/koa-audit-log.js';
import koaGuard from '#src/middleware/koa-guard.js';
import assertThat from '#src/utils/assert-that.js';

import { type AnonymousRouter, type RouterInitArgs } from '../types.js';

import { experienceApiRoutesPrefix, experienceIdentificationApiRoutesPrefix } from './const.js';
import koaInteractionSession, {
  type WithInteractionSessionContext,
} from './middleware/koa-interaction-session.js';
import passwordVerificationRoutes from './verification-routes/password-verification.js';

type RouterContext<T> = T extends Router<unknown, infer Context> ? Context : never;

export default function experienceApiRoutes<T extends AnonymousRouter>(
  ...[anonymousRouter, tenant]: RouterInitArgs<T>
) {
  const { queries, libraries } = tenant;

  const router =
    // @ts-expect-error for good koa types
    // eslint-disable-next-line no-restricted-syntax
    (anonymousRouter as Router<unknown, WithInteractionSessionContext<RouterContext<T>>>).use(
      koaAuditLog(queries),
      koaInteractionSession(tenant)
    );

  router.post(
    experienceIdentificationApiRoutesPrefix,
    koaGuard({
      body: identificationApiPayloadGuard,
      status: [204, 400, 404],
    }),
    async (ctx, next) => {
      const { interactionEvent, verificationId } = ctx.guard.body;

      ctx.interactionSession.setInteractionEvent(interactionEvent);

      const verificationRecord = ctx.interactionSession.getVerificationRecordById(verificationId);

      assertThat(
        verificationRecord,
        new RequestError({ code: 'session.verification_session_not_found', status: 404 })
      );

      ctx.interactionSession.identifyUser(verificationRecord);

      await ctx.interactionSession.save();

      ctx.status = 204;

      return next();
    }
  );

  router.post(
    `${experienceApiRoutesPrefix}/submit`,
    koaGuard({
      status: [200],
    }),
    async (ctx, next) => {
      await ctx.interactionSession.submit();
      ctx.status = 200;
      return next();
    }
  );
  passwordVerificationRoutes(router, tenant);
}
