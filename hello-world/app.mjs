export const lambdaHandler = async (event, context) => {
  console.log("Event:", JSON.stringify(event, null, 2));

  const subject = event.headers && event.headers["X-Client-Cert-Subject"];
  const response = {
    clientCertSubject: subject || "Not available",
  };

  return response;
};
