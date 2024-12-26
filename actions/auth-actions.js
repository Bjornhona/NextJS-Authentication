'use server';
import { createUser, getUserByEmail } from '../lib/user';
import { hashUserPassword, verifyPassword } from '../lib/hash';
import { redirect } from 'next/navigation';
import { createAuthSession, destroyAuthSession } from '../lib/auth';

export const signup = async (prevState, formData) => { // by default a form allways sends prevState and formData.
  const email = formData.get('email'); // the asigned name in the auth-form.
  const password = formData.get('password');

  // 1) Validate email and password, return if any errors.
  let errors = {};
  if (!email.includes('@') || !email.includes('.')) {
    errors.email = 'Please enter a valid email address.';
  }
  if (password.trim().length < 8) {
    errors.password = 'Password must be at least 8 characters long.';
  }
  if (Object.keys(errors).length > 0) {
    return { errors };
  }

  // 2) Store it in the database (create new user)
  const hashedPassword = hashUserPassword(password);
  try {
    const userId = createUser(email, hashedPassword);
    await createAuthSession(userId);
    // 3) Redirect to the training page
    redirect('/training');
  } catch (error) {
    if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      errors.email = 'Email is already in use.';
      return { errors };
    }
    throw error;
  }
};

export const login = async (prevState, formData) => {
  const email = formData.get('email');
  const password = formData.get('password');
  const errorMessage = 'Could not authenticate user, please check your credentials.';

  // 1) Validate email and password, return if any errors.
  const existingUser = getUserByEmail(email);
  if (!existingUser) {
    return { errors: { email: errorMessage } };
  }

  const isValidPassword = verifyPassword(existingUser.password, password);
  if (!isValidPassword) {
    return { errors: { password: errorMessage} };
  }

  // 2) Create session and redirect to training page
  await createAuthSession(existingUser.id);
  redirect('/training');
}

export const logout = async () => {
  await destroyAuthSession();
  redirect('/');
};

export const auth = (mode, prevState, formData) => {
  if (mode === 'login') {
    return login(prevState, formData);
  } else {
    return signup(prevState, formData);
  }
}
