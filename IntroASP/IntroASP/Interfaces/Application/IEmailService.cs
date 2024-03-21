using IntroASP.Application.DTOs;

namespace IntroASP.Interfaces.Application
{
    public interface IEmailService
    {
        Task SendEmailAsyncRegister(DTOEmail userData);
        Task SendEmailAsyncResetPassword(DTOEmail userDataResetPassword);
    }
}
