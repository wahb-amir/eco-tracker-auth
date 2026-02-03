import nodemailer from "nodemailer";
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Send verification email
async function sendVerificationEmail(toEmail, token) {
  const verificationLink = `https://yourapp.com/verify?token=${token}`;

  const mailOptions = {
    from: `"Your App" <${process.env.EMAIL_USER}>`,
    to: toEmail,
    subject: "Verify Your Account",
    html: `
      <!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Verify Your Eco-Tracker Account</title>
</head>
<body style="margin:0; padding:0; font-family: Arial, sans-serif; background-color:#f4f4f4;">

  <table width="100%" cellpadding="0" cellspacing="0">
    <tr>
      <td align="center">
        <!-- Main container -->
        <table width="600" cellpadding="0" cellspacing="0" style="background-color:#ffffff; border-radius:8px; margin:20px auto; padding:20px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
          
          <!-- Header / Logo -->
          <tr>
            <td align="center" style="padding-bottom:20px;">
              <img src="https://yourdomain.com/logo.png" alt="Eco-Tracker Logo" width="80" style="display:block;">
            </td>
          </tr>
          
          <!-- Title -->
          <tr>
            <td style="text-align:center; font-size:24px; font-weight:bold; color:#2e7d32; padding-bottom:10px;">
              Verify Your Eco-Tracker Account
            </td>
          </tr>

          <!-- Message -->
          <tr>
            <td style="text-align:center; font-size:16px; color:#555555; padding:0 30px 20px 30px;">
              Thanks for signing up for Eco-Tracker! Click the button below to verify your email address and start tracking your eco-friendly journey.
            </td>
          </tr>

          <!-- Verify Button -->
          <tr>
            <td align="center" style="padding-bottom:20px;">
              <a href="{{VERIFICATION_LINK}}" style="background-color:#2e7d32; color:#ffffff; text-decoration:none; padding:12px 25px; border-radius:5px; font-weight:bold; display:inline-block;">
                Verify Email
              </a>
            </td>
          </tr>

          <!-- Fallback Link -->
          <tr>
            <td style="text-align:center; font-size:14px; color:#999999; padding-bottom:20px;">
              Or copy and paste this link into your browser:<br>
              <a href="{{VERIFICATION_LINK}}" style="color:#2e7d32; text-decoration:none;">{{VERIFICATION_LINK}}</a>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="text-align:center; font-size:12px; color:#999999; padding-top:10px;">
              © 2026 Eco-Tracker. All rights reserved.
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>

</body>
</html>

    `,
  };

  await transporter.sendMail(mailOptions);
}

module.exports = { sendVerificationEmail };
