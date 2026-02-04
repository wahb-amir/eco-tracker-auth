// mail/sendOtpEmail.js
import nodemailer from "nodemailer";

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS, // use an app password for Gmail in production
  },
});

/**
 * Send the user a numeric OTP for verification.
 * @param {string} toEmail - recipient email
 * @param {string} otp - the OTP code (plain string, e.g. "123456")
 * @param {object} [opts] - optional extras { expiryMinutes, origin }
 */
export async function sendOtpEmail(toEmail, otp, opts = {}) {
  if (!toEmail) throw new Error("toEmail is required");
  if (!otp) throw new Error("otp is required");

  const expiryMinutes = opts.expiryMinutes ?? 60;
  const origin = opts.origin ?? process.env.ORIGIN ?? "";

  const verifyUrl = origin ? `${origin.replace(/\/$/, "")}/verify?email=${encodeURIComponent(toEmail)}` : "";

  const mailOptions = {
    from: `"Eco Tracker" <${process.env.EMAIL_USER}>`,
    to: toEmail,
    subject: "Your Eco-Tracker verification code",
    text: `Your Eco-Tracker verification code is: ${otp}\n\nIt expires in ${expiryMinutes} minutes.\n\n${verifyUrl ? `Open: ${verifyUrl}` : ""}`,
    html: `
      <!doctype html>
      <html lang="en">
      <head>
        <meta charset="utf-8"/>
        <meta name="viewport" content="width=device-width, initial-scale=1"/>
        <title>Verify your Eco-Tracker account</title>
      </head>
      <body style="margin:0;padding:0;font-family:Inter, system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial;">
        <table cellpadding="0" cellspacing="0" width="100%" style="background:#f4f6f8;padding:24px 0;">
          <tr>
            <td align="center">
              <table width="600" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 6px 30px rgba(2,6,23,0.08);">
                <tr>
                  <td style="padding:28px 32px;text-align:center;">
                    <img src="${origin ? `${origin.replace(/\/$/, "")}/logo.png` : ""}" alt="Eco-Tracker" width="72" style="display:block;margin:0 auto 12px auto;">
                    <h1 style="margin:0;font-size:20px;color:#1f7a3a;">Your verification code</h1>
                    <p style="color:#495057;margin:8px 0 20px;">Use the code below to verify your Eco-Tracker account. It expires in <strong>${expiryMinutes} minutes</strong>.</p>

                    <!-- OTP box -->
                    <div style="display:inline-block;padding:18px 22px;border-radius:10px;background:linear-gradient(180deg,#f7fff9,#effef0);border:1px solid #e6f6ea;box-shadow:0 4px 12px rgba(31,122,58,0.08);">
                      <div style="font-family:monospace,ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;font-size:28px;letter-spacing:4px;color:#0f5132;">
                        ${otp}
                      </div>
                    </div>

                    ${verifyUrl ? `<div style="margin-top:18px;"><a href="${verifyUrl}" style="background:#1f7a3a;color:#fff;padding:10px 18px;border-radius:8px;text-decoration:none;display:inline-block;font-weight:600;">Open verification page</a></div>` : ""}

                    <p style="color:#9aa4a8;font-size:13px;margin-top:20px;line-height:1.4;">
                      If you didn't request this, ignore this email. This code will expire after ${expiryMinutes} minutes.
                    </p>

                    <hr style="border:none;border-top:1px solid #eef2f4;margin:20px 0 12px;">
                    <p style="color:#96a0a4;font-size:12px;margin:0;">© ${new Date().getFullYear()} Eco-Tracker. All rights reserved.</p>
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

  const info = await transporter.sendMail(mailOptions);
  return info;
}
