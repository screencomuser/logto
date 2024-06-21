import {
  VerificationType,
  interactionIdentifierGuard,
  type InteractionIdentifier,
} from '@logto/schemas';
import { type ToZodObject } from '@logto/schemas/lib/utils/zod.js';
import { generateStandardId } from '@logto/shared';
import { z } from 'zod';

import RequestError from '#src/errors/RequestError/index.js';
import type Libraries from '#src/tenants/Libraries.js';
import type Queries from '#src/tenants/Queries.js';
import assertThat from '#src/utils/assert-that.js';

import { findUserByIdentifier } from '../../utils.js';

import { type Verification } from './verification.js';

export type PasswordVerificationRecordData = {
  id: string;
  type: VerificationType.Password;
  identifier: InteractionIdentifier;
  userId?: string;
};

export const passwordVerificationRecordDataGuard = z.object({
  id: z.string(),
  type: z.literal(VerificationType.Password),
  identifier: interactionIdentifierGuard,
  userId: z.string().optional(),
}) satisfies ToZodObject<PasswordVerificationRecordData>;

/**
 * PasswordVerification is a verification record that verifies a user's identity
 * using identifier and password
 */
export class PasswordVerification implements Verification {
  /** Factory method to create a new PasswordVerification record using the given identifier */
  static create(libraries: Libraries, queries: Queries, identifier: InteractionIdentifier) {
    return new PasswordVerification(libraries, queries, {
      id: generateStandardId(),
      type: VerificationType.Password,
      identifier,
    });
  }

  readonly type = VerificationType.Password;
  public readonly identifier: InteractionIdentifier;
  public readonly id: string;
  /* The userId of the user that has been identifier by the given identifier and password */
  private userId?: string;

  constructor(
    private readonly libraries: Libraries,
    private readonly queries: Queries,
    data: PasswordVerificationRecordData
  ) {
    const { id, identifier, userId } = data;

    this.id = id;
    this.identifier = identifier;
    this.userId = userId;
  }

  /** Returns true if a userId is set */
  get isVerified() {
    return this.userId !== undefined;
  }

  get verifiedUserId() {
    return this.userId;
  }

  /** Verifies the password and sets the userId */
  async verify(password: string) {
    const user = await findUserByIdentifier(this.queries.users, this.identifier);

    // Throws an 422 error if the user is not found or the password is incorrect
    const { isSuspended, id } = await this.libraries.users.verifyUserPassword(user, password);

    assertThat(!isSuspended, new RequestError({ code: 'user.suspended', status: 401 }));

    this.userId = id;
  }

  toJson(): PasswordVerificationRecordData {
    return {
      id: this.id,
      type: this.type,
      identifier: this.identifier,
      userId: this.userId,
    };
  }
}
