using System;
using System.IO;
using System.Threading.Tasks;
using System.Collections.Concurrent;
using System.Timers;

namespace Monitoramento
{
    public class Detection
    {
        private static readonly ConcurrentDictionary<string, int> contadorEventos = new();
        private static readonly System.Timers.Timer timerLimpeza = new(5000);

        public Detection()
        {
            timerLimpeza.Elapsed += (s, e) => contadorEventos.Clear();
            timerLimpeza.AutoReset = true;
            timerLimpeza.Start();
        }
        
        /* private readonly Protection protect = new();
        protect.Protector(...); */

        public async Task Detector(string fileWay)
        {
            // VERIFICANDO ESTABILIDADE ---------------------------------------------------|
            Console.WriteLine($"Verificando arquivo {fileWay}...");
            bool estaEstavel = await Stability(fileWay);

            if (estaEstavel)
            {
                Console.WriteLine($"Arquivo {fileWay} está estável. Iniciando análise...");

                // VERIFICANDO EXTENSÃO SUSPEITA ---------------------------------------------------|
                if (VerificarExtensaoSuspeita(fileWay))
                {
                    Console.WriteLine("🚨 Extensão suspeita detectada. Pode indicar ransomware.");
                }
                else
                {
                    Console.WriteLine("✅ Extensão aparentemente segura.");
                }

                // VERIFICANDO NÍVEL DE ENTROPIA ---------------------------------------------------|
                double entropia = CalcularEntropia(fileWay);
                Console.WriteLine($"Entropia do arquivo: {entropia:F4}");

                if (entropia > 5.35)
                {
                    Console.WriteLine("⚠️ Arquivo com alta entropia. Possível criptografia detectada.");
                }
                else
                {
                    Console.WriteLine("✅ Entropia dentro do padrão esperado.");
                }

                // VERIFICANDO MODIFICAÇÕES EM MASSA ---------------------------------------------------|
                string pasta = Path.GetDirectoryName(fileWay);
                if (DetectarModificacaoEmMassa(pasta))
                {
                    Console.WriteLine("🚨 Modificações em massa detectadas nesse diretório.");
                }

                // VERIFICANDO CRIAÇÃO DE .EXE OU .BMP EM LOCAL SENSÍVEL -----------------------------|
                if (VerificarCriacaoSuspeita(fileWay))
                {
                    Console.WriteLine("🚨 Criação de .exe ou .bmp em local sensível. Pode indicar ransomware.");
                }
            }
            else
            {
                Console.WriteLine($"Arquivo {fileWay} não está acessível ou foi removido.");
            }
        }

        public async Task<bool> Stability(string caminho, int delay = 100)
        {
            if (!File.Exists(caminho))
            {
                return false;
            }

            while (true)
            {
                await Task.Delay(delay);

                try
                {
                    using var fs = new FileStream(caminho, FileMode.Open, FileAccess.Read, FileShare.None);
                    long tamanho1 = fs.Length;
                    await Task.Delay(50);
                    long tamanho2 = fs.Length;

                    if (tamanho1 == tamanho2)
                    {
                        return true;
                    }
                }
                catch (IOException)
                {
                    // Arquivo ainda em uso (instável)
                }
            }
        }

        public double CalcularEntropia(string caminho)
        {
            if (!File.Exists(caminho)) return 0;

            byte[] dados = File.ReadAllBytes(caminho);
            if (dados.Length == 0) return 0;

            int[] frequencias = new int[256];
            foreach (byte b in dados)
            {
                frequencias[b]++;
            }

            double entropia = 0;
            foreach (int freq in frequencias)
            {
                if (freq == 0) continue;
                double p = (double)freq / dados.Length;
                entropia -= p * Math.Log2(p);
            }

            return entropia;
        }

        public bool VerificarExtensaoSuspeita(string caminho)
        {
            string[] extensoesSuspeitas = {
                ".wncry", ".wcry", ".wncryt", ".wncrypt", ".locky", ".crypt", ".enc", ".r5a", ".cerber",
                ".crypted", ".cryp1", ".crypz", ".wallet", ".help", ".thor", ".zzzzz", ".aes256", ".vault"
            };
            string extensao = Path.GetExtension(caminho)?.ToLower();

            return Array.Exists(extensoesSuspeitas, ext => ext == extensao);
        }

        public bool DetectarModificacaoEmMassa(string diretorio)
        {
            if (!contadorEventos.ContainsKey(diretorio))
                contadorEventos[diretorio] = 0;

            contadorEventos[diretorio]++;
            return contadorEventos[diretorio] > 10;
        }

        public bool VerificarCriacaoSuspeita(string caminho)
        {
            string extensao = Path.GetExtension(caminho)?.ToLower();
            if (extensao != ".exe" && extensao != ".bmp") return false;

            string[] pastasCriticas = {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)
            };

            string pastaArquivo = Path.GetDirectoryName(caminho);
            foreach (var pasta in pastasCriticas)
            {
                if (pastaArquivo.StartsWith(pasta, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }
    }
}