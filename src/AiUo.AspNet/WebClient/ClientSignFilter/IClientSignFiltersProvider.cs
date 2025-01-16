using AiUo.Configuration;

namespace AiUo.AspNet;

public interface IClientSignFiltersProvider
{
    List<ClientSignFilterElement> Build();
}