import '../globals.css';
import { logout } from '@/actions/auth-actions';

export const metadata = {
  title: 'Next Auth',
  description: 'Next.js Authentication',
};

const AuthRootLayout = ({ children }) => {
  return (
    <>
      <header id="auth-header">
        <p>Welcome back!</p>
        <form action={logout}><button>Log out</button></form>
      </header>
      {children}
    </>
  );
}

export default AuthRootLayout;
