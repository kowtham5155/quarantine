import type { Metadata } from 'next';

import { ForgotPasswordForm } from '@/app/(auth)/forgot-password/ForgotPasswordForm';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';

export const metadata: Metadata = {
  title: 'Reset your password',
  robots: { index: false, follow: false },
};

export default function ForgotPasswordPage() {
  return (
    <Card>
      <CardHeader className="gap-1">
        <CardTitle className="text-xl">Reset your password</CardTitle>
        <CardDescription>
          A reset link can only reach you by email, and this deployment has no mail provider
          configured — so nothing can be delivered. Adding one makes this work as it stands.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <ForgotPasswordForm />
      </CardContent>
    </Card>
  );
}
