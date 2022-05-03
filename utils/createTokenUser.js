const createTokenUser = (user) => {
    return { name: user.name, lastname: user.lastname, userId: user._id };
  };
  
module.exports = createTokenUser;
  