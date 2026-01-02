import Mailgen from "mailgen"; // creating an email
import nodemailer from "nodemailer";


const sendEmail = async (options) =>{
  const mailGenerator=new Mailgen({
    theme:"default",
    product:{
      name :"Task Manager",
      link:"https://taskmanagerlink.com"
    }
  })

  const emailTextual=mailGenerator.generatePlaintext(options.mailgenContent)
  const emailHtml=mailGenerator.generate(options.mailgenContent)

  const transporter=nodemailer.createTransport({
    host:process.env.MAILTRAP_SMTP_HOST,
    port:process.env.MAILTRAP_SMTP_PORT,
    auth:{
      user:process.env.MAILTRAP_SMTP_USER,
      pass:process.env.MAILTRAP_SMTP_PASS
    }
  })
  const mail={
     from:"mail.taskmanager@example.com",
     to: options.email,
     subject:options.subject,
     text:emailTextual,
     html:emailHtml
  }
  try {
    await transporter.sendMail(mail)
  } catch (error) {
    console.error("Email service failed silently.Make sure you have provided your MAILTRAP credentials in the .env file")
    console.error(error)
  }
}

const emailVerificationMailgenContent = (username, verificationUrl) => {
  return {
    body: {
      name: username,
      intro: "Welcome to our App! We're excited to have you on board.",
      action: {
        instructions: "To verify your email, please click on the button below:",
        button: {
          color: "#22BC69",
          text: "Verify your email",
          link: verificationUrl,
        },
      },
      outro: "Need help or have questions? Just reply to this email.",
    },
  };
};

const forgotPasswordMailgenContent = (username, passwordResetUrl) => {
  return {
    body: {
      name: username,
      intro: "We received a request to reset your account password.",
      action: {
        instructions: "To reset your password, click the button below:",
        button: {
          color: "#FF6B6B",
          text: "Reset Password",
          link: passwordResetUrl,
        },
      },
      outro: "If you didn’t request this, you can safely ignore this email.",
    },
  };
};

export {
  emailVerificationMailgenContent,
  forgotPasswordMailgenContent,
  sendEmail,
};
