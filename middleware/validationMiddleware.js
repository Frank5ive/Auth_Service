export const validate = (schema) => (req, reply, done) => {
  try {
    schema.parse(req.body);
    done();
  } catch (error) {
    reply.status(400).send({ errors: error.errors });
  }
};
