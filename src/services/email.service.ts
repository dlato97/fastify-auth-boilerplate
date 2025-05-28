import type { Transporter } from 'nodemailer'
import { createTransport } from 'nodemailer'
import { config } from '@/config/config.js'
import { emailLogger, logger } from '@/utils/logger.js'

export interface EmailOptions {
  to: string
  subject: string
  html: string
  text?: string
  attachments?: Array<{
    filename: string
    content: string | Buffer
    contentType?: string
  }>
}

class EmailService {
  private transporter: Transporter

  constructor() {
    this.transporter = createTransport({
      host: config.email.host,
      port: config.email.port,
      secure: config.email.port === 465,
      auth:
        config.email.user && config.email.pass
          ? {
              user: config.email.user,
              pass: config.email.pass
            }
          : undefined,
      // Development settings for MailHog
      ...(config.isDevelopment && {
        ignoreTLS: true,
        requireTLS: false
      })
    })

    // Verify connection on startup
    this.verifyConnection().catch(error => {
      logger.error('Failed to verify email connection:', error)
    })
  }

  private async verifyConnection(): Promise<void> {
    try {
      await this.transporter.verify()
      emailLogger.info('✅ Email service connected successfully')
    } catch (error) {
      emailLogger.error(error, '❌ Email service connection failed')
    }
  }

  async sendEmail(options: EmailOptions): Promise<void> {
    try {
      const info = await this.transporter.sendMail({
        from: `${config.email.fromName} <${config.email.from}>`,
        to: options.to,
        subject: options.subject,
        html: options.html,
        text: options.text,
        attachments: options.attachments
      })

      emailLogger.info(
        {
          to: options.to,
          subject: options.subject,
          messageId: info.messageId,
          accepted: info.accepted,
          rejected: info.rejected
        },
        'Email sent successfully'
      )
    } catch (error) {
      emailLogger.error(
        {
          error,
          to: options.to,
          subject: options.subject
        },
        'Failed to send email'
      )
      throw error
    }
  }

  // Email templates
  private generateEmailTemplate(
    title: string,
    content: string,
    actionButton?: { text: string; url: string }
  ): string {
    return `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>${title}</title>
        <style>
          body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f8f9fa;
          }
          .email-container {
            background: white;
            border-radius: 8px;
            padding: 40px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
          }
          .header {
            text-align: center;
            margin-bottom: 30px;
          }
          .logo {
            font-size: 24px;
            font-weight: bold;
            color: #007bff;
            margin-bottom: 10px;
          }
          .title {
            font-size: 20px;
            font-weight: 600;
            color: #212529;
            margin-bottom: 20px;
          }
          .content {
            font-size: 16px;
            margin-bottom: 30px;
            color: #495057;
          }
          .action-button {
            display: inline-block;
            background-color: #007bff;
            color: white;
            padding: 12px 24px;
            text-decoration: none;
            border-radius: 6px;
            font-weight: 500;
            margin: 20px 0;
            text-align: center;
          }
          .action-button:hover {
            background-color: #0056b3;
          }
          .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #dee2e6;
            font-size: 14px;
            color: #6c757d;
            text-align: center;
          }
          .security-notice {
            background-color: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 4px;
            padding: 15px;
            margin: 20px 0;
            font-size: 14px;
            color: #856404;
          }
          .code {
            background-color: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 4px;
            padding: 15px;
            font-family: 'Monaco', 'Consolas', monospace;
            font-size: 18px;
            text-align: center;
            letter-spacing: 2px;
            margin: 20px 0;
          }
        </style>
      </head>
      <body>
        <div class="email-container">
          <div class="header">
            <div class="logo">Your App</div>
            <h1 class="title">${title}</h1>
          </div>
          
          <div class="content">
            ${content}
          </div>
          
          ${
            actionButton
              ? `
            <div style="text-align: center;">
              <a href="${actionButton.url}" class="action-button">${actionButton.text}</a>
            </div>
          `
              : ''
          }
          
          <div class="footer">
            <p>This email was sent from ${config.urls.app}</p>
            <p>If you didn't request this, please ignore this email or contact support.</p>
          </div>
        </div>
      </body>
      </html>
    `
  }

  // Welcome email
  async sendWelcomeEmail(email: string, name?: string): Promise<void> {
    const content = `
      <p>Hello${name ? ` ${name}` : ''}!</p>
      <p>Welcome to our platform! We're excited to have you on board.</p>
      <p>Your account has been successfully created. You can now access all our features and services.</p>
      <p>If you have any questions or need assistance, don't hesitate to reach out to our support team.</p>
    `

    await this.sendEmail({
      to: email,
      subject: 'Welcome to Your App!',
      html: this.generateEmailTemplate('Welcome!', content, {
        text: 'Get Started',
        url: `${config.urls.frontend}/dashboard`
      })
    })
  }

  // Email verification
  async sendVerificationEmail(email: string, token: string): Promise<void> {
    const verificationUrl = `${config.urls.frontend}/verify-email?token=${token}`

    const content = `
      <p>Thank you for signing up! To complete your registration, please verify your email address.</p>
      <p>Click the button below to verify your email:</p>
      <div class="security-notice">
        <strong>Security Note:</strong> This link will expire in 24 hours for your security.
      </div>
      <p>If you didn't create an account, please ignore this email.</p>
    `

    await this.sendEmail({
      to: email,
      subject: 'Verify Your Email Address',
      html: this.generateEmailTemplate('Verify Your Email', content, {
        text: 'Verify Email Address',
        url: verificationUrl
      }),
      text: `Please verify your email by visiting: ${verificationUrl}`
    })
  }

  // Password reset email
  async sendPasswordResetEmail(email: string, token: string): Promise<void> {
    const resetUrl = `${config.urls.frontend}/reset-password?token=${token}`

    const content = `
      <p>We received a request to reset your password. If you made this request, click the button below to reset your password:</p>
      <div class="security-notice">
        <strong>Security Note:</strong> This link will expire in 1 hour for your security.
      </div>
      <p>If you didn't request a password reset, please ignore this email. Your password will remain unchanged.</p>
    `

    await this.sendEmail({
      to: email,
      subject: 'Reset Your Password',
      html: this.generateEmailTemplate('Reset Your Password', content, {
        text: 'Reset Password',
        url: resetUrl
      }),
      text: `Reset your password by visiting: ${resetUrl}`
    })
  }

  // Password changed notification
  async sendPasswordChangedEmail(email: string, ipAddress: string): Promise<void> {
    const content = `
      <p>Your password has been successfully changed.</p>
      <p><strong>Details:</strong></p>
      <ul>
        <li>Date: ${new Date().toLocaleString()}</li>
        <li>IP Address: ${ipAddress}</li>
      </ul>
      <div class="security-notice">
        <strong>Didn't change your password?</strong> If you didn't make this change, please contact our support team immediately.
      </div>
    `

    await this.sendEmail({
      to: email,
      subject: 'Password Changed Successfully',
      html: this.generateEmailTemplate('Password Changed', content, {
        text: 'Contact Support',
        url: `${config.urls.frontend}/support`
      })
    })
  }

  // Two-factor authentication enabled
  async send2FAEnabledEmail(email: string): Promise<void> {
    const content = `
      <p>Two-factor authentication has been successfully enabled for your account.</p>
      <p>Your account is now more secure! You'll need to provide a verification code from your authenticator app when signing in.</p>
      <div class="security-notice">
        <strong>Keep your backup codes safe!</strong> Make sure to store your backup codes in a secure location. You can use them to access your account if you lose your authenticator device.
      </div>
    `

    await this.sendEmail({
      to: email,
      subject: 'Two-Factor Authentication Enabled',
      html: this.generateEmailTemplate('2FA Enabled', content)
    })
  }

  // Two-factor authentication disabled
  async send2FADisabledEmail(email: string, ipAddress: string): Promise<void> {
    const content = `
      <p>Two-factor authentication has been disabled for your account.</p>
      <p><strong>Details:</strong></p>
      <ul>
        <li>Date: ${new Date().toLocaleString()}</li>
        <li>IP Address: ${ipAddress}</li>
      </ul>
      <div class="security-notice">
        <strong>Didn't disable 2FA?</strong> If you didn't make this change, please secure your account immediately and contact our support team.
      </div>
    `

    await this.sendEmail({
      to: email,
      subject: 'Two-Factor Authentication Disabled',
      html: this.generateEmailTemplate('2FA Disabled', content, {
        text: 'Secure My Account',
        url: `${config.urls.frontend}/security`
      })
    })
  }

  // Login alert (suspicious login)
  async sendLoginAlertEmail(
    email: string,
    ipAddress: string,
    userAgent: string,
    location?: string
  ): Promise<void> {
    const content = `
      <p>We detected a new sign-in to your account from an unrecognized device or location.</p>
      <p><strong>Sign-in details:</strong></p>
      <ul>
        <li>Date: ${new Date().toLocaleString()}</li>
        <li>IP Address: ${ipAddress}</li>
        <li>Device: ${userAgent}</li>
        ${location ? `<li>Location: ${location}</li>` : ''}
      </ul>
      <div class="security-notice">
        <strong>Was this you?</strong> If you signed in from a new device or location, you can ignore this email. If you don't recognize this activity, please secure your account immediately.
      </div>
    `

    await this.sendEmail({
      to: email,
      subject: 'New Sign-in to Your Account',
      html: this.generateEmailTemplate('Security Alert', content, {
        text: 'Secure My Account',
        url: `${config.urls.frontend}/security`
      })
    })
  }

  // Account locked notification
  async sendAccountLockedEmail(email: string, unlockTime?: Date): Promise<void> {
    const content = `
      <p>Your account has been temporarily locked due to multiple failed sign-in attempts.</p>
      ${
        unlockTime
          ? `
        <p><strong>Your account will be automatically unlocked at:</strong><br>
        ${unlockTime.toLocaleString()}</p>
      `
          : ''
      }
      <div class="security-notice">
        <strong>Didn't try to sign in?</strong> Someone may be trying to access your account. Consider changing your password once your account is unlocked.
      </div>
    `

    await this.sendEmail({
      to: email,
      subject: 'Account Temporarily Locked',
      html: this.generateEmailTemplate('Account Locked', content, {
        text: 'Contact Support',
        url: `${config.urls.frontend}/support`
      })
    })
  }

  // Account reactivated
  async sendAccountReactivatedEmail(email: string): Promise<void> {
    const content = `
      <p>Great news! Your account has been reactivated and is now fully accessible.</p>
      <p>You can now sign in and use all features of your account normally.</p>
      <p>If you have any questions or need assistance, please don't hesitate to contact our support team.</p>
    `

    await this.sendEmail({
      to: email,
      subject: 'Account Reactivated',
      html: this.generateEmailTemplate('Account Reactivated', content, {
        text: 'Sign In Now',
        url: `${config.urls.frontend}/login`
      })
    })
  }

  // Role assignment notification
  async sendRoleAssignedEmail(email: string, roleName: string, assignedBy: string): Promise<void> {
    const content = `
      <p>You have been assigned a new role in the system.</p>
      <p><strong>Role Details:</strong></p>
      <ul>
        <li>Role: ${roleName}</li>
        <li>Assigned by: ${assignedBy}</li>
        <li>Date: ${new Date().toLocaleString()}</li>
      </ul>
      <p>This role may grant you additional permissions and access to new features.</p>
    `

    await this.sendEmail({
      to: email,
      subject: 'New Role Assigned',
      html: this.generateEmailTemplate('Role Assignment', content, {
        text: 'View Dashboard',
        url: `${config.urls.frontend}/dashboard`
      })
    })
  }

  // System maintenance notification
  async sendMaintenanceNotificationEmail(
    email: string,
    startTime: Date,
    endTime: Date,
    description: string
  ): Promise<void> {
    const content = `
      <p>We wanted to let you know about upcoming scheduled maintenance that may temporarily affect our services.</p>
      <p><strong>Maintenance Details:</strong></p>
      <ul>
        <li>Start: ${startTime.toLocaleString()}</li>
        <li>End: ${endTime.toLocaleString()}</li>
        <li>Description: ${description}</li>
      </ul>
      <p>During this time, you may experience brief interruptions in service. We apologize for any inconvenience.</p>
    `

    await this.sendEmail({
      to: email,
      subject: 'Scheduled Maintenance Notification',
      html: this.generateEmailTemplate('Scheduled Maintenance', content)
    })
  }

  // Backup codes generated
  async sendBackupCodesEmail(email: string, backupCodes: string[]): Promise<void> {
    const codesHtml = backupCodes.map(code => `<div class="code">${code}</div>`).join('')

    const content = `
      <p>Here are your new backup codes for two-factor authentication:</p>
      ${codesHtml}
      <div class="security-notice">
        <strong>Important:</strong>
        <ul>
          <li>Keep these codes in a safe place</li>
          <li>Each code can only be used once</li>
          <li>Use them if you lose access to your authenticator app</li>
          <li>Generate new codes if you suspect they've been compromised</li>
        </ul>
      </div>
    `

    await this.sendEmail({
      to: email,
      subject: 'Your New Backup Codes',
      html: this.generateEmailTemplate('Backup Codes', content)
    })
  }

  // Generic notification email
  async sendNotificationEmail(
    email: string,
    subject: string,
    title: string,
    message: string,
    actionButton?: { text: string; url: string }
  ): Promise<void> {
    await this.sendEmail({
      to: email,
      subject,
      html: this.generateEmailTemplate(title, `<p>${message}</p>`, actionButton)
    })
  }

  // Bulk email sending (for newsletters, announcements, etc.)
  async sendBulkEmail(
    recipients: string[],
    subject: string,
    content: string,
    batchSize: number = 50
  ): Promise<void> {
    const batches = []
    for (let i = 0; i < recipients.length; i += batchSize) {
      batches.push(recipients.slice(i, i + batchSize))
    }

    for (const batch of batches) {
      const promises = batch.map(recipient =>
        this.sendEmail({
          to: recipient,
          subject,
          html: content
        }).catch(error => {
          emailLogger.error(
            {
              error,
              recipient,
              subject
            },
            'Failed to send bulk email to recipient'
          )
        })
      )

      await Promise.all(promises)

      // Small delay between batches to avoid overwhelming the SMTP server
      if (batches.indexOf(batch) < batches.length - 1) {
        await new Promise(resolve => setTimeout(resolve, 1000))
      }
    }

    emailLogger.info(
      {
        totalRecipients: recipients.length,
        batchCount: batches.length,
        subject
      },
      'Bulk email sending completed'
    )
  }

  // Email template testing (development only)
  async sendTestEmail(email: string, templateName: string): Promise<void> {
    if (!config.isDevelopment) {
      throw new Error('Test emails can only be sent in development mode')
    }

    const testData = {
      verification: () => this.sendVerificationEmail(email, 'test-token'),
      welcome: () => this.sendWelcomeEmail(email, 'Test User'),
      passwordReset: () => this.sendPasswordResetEmail(email, 'test-token'),
      passwordChanged: () => this.sendPasswordChangedEmail(email, '127.0.0.1'),
      '2faEnabled': () => this.send2FAEnabledEmail(email),
      '2faDisabled': () => this.send2FADisabledEmail(email, '127.0.0.1'),
      loginAlert: () => this.sendLoginAlertEmail(email, '127.0.0.1', 'Test Browser'),
      accountLocked: () => this.sendAccountLockedEmail(email, new Date(Date.now() + 3600000)),
      backupCodes: () => this.sendBackupCodesEmail(email, ['ABC123', 'DEF456', 'GHI789'])
    }

    const testFunction = testData[templateName as keyof typeof testData]
    if (!testFunction) {
      throw new Error(`Unknown template: ${templateName}`)
    }

    await testFunction()
    emailLogger.info({ email, templateName }, 'Test email sent')
  }
}

export const emailService = new EmailService()
