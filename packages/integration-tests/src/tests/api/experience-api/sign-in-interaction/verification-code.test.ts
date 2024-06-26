import { deleteUser } from '#src/api/admin-user.js';
import { signInWithVerificationCode } from '#src/helpers/experience/index.js';
import { enableAllVerificationCodeSignInMethods } from '#src/helpers/sign-in-experience.js';
import { generateNewUser } from '#src/helpers/user.js';
import { devFeatureTest } from '#src/utils.js';

const verificationIdentifierType: readonly ['email', 'phone'] = Object.freeze(['email', 'phone']);

const identifiersTypeToUserProfile = Object.freeze({
  email: 'primaryEmail',
  phone: 'primaryPhone',
});

devFeatureTest.describe('Sign-in with verification code happy path', () => {
  beforeAll(async () => {
    await enableAllVerificationCodeSignInMethods();
  });

  it.each(verificationIdentifierType)(
    'Should sign-in with verification code using %p',
    async (identifier) => {
      const { userProfile, user } = await generateNewUser({
        [identifiersTypeToUserProfile[identifier]]: true,
        password: true,
      });

      await signInWithVerificationCode({
        type: identifier,
        value: userProfile[identifiersTypeToUserProfile[identifier]]!,
      });

      await deleteUser(user.id);
    }
  );
});
