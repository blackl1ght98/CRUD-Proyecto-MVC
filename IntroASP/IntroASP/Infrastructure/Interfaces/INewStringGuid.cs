using IntroASP.Models;

namespace IntroASP.Infrastructure.Interfaces
{
    public interface INewStringGuid
    {
        Task SaveNewStringGuid(Usuario operation);
    }
}
