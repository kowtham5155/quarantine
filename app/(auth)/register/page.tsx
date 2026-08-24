import type { Metadata } from 'next';

import { RegisterForm } from '@/app/(auth)/register/RegisterForm';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';

export const metadata: Metadata = {
  title: 'Create an account',
  description: 'Create a Quarantine account.',
  robots: { index: false, follow: false },
};

export default function RegisterPage() {
  return (
    <Card>
      <CardHeader className="gap-1">
        <CardTitle className="text-xl">Create an account</CardTitle>
        <CardDescription>
          Scan your dependencies before they reach a developer machine or a CI runner.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <RegisterForm />
      </CardContent>
    </Card>
  );
}
