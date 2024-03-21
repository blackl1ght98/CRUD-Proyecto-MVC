using IntroASP.Models;

namespace IntroASP.Interfaces.Infrastructure
{
    public interface INewStringGuid
    {
        Task SaveNewStringGuid(Usuario operation);
    }
}
