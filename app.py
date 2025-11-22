import io
from typing import List, Dict, Any

import streamlit as st
import pandas as pd
import yaml
from lxml import etree

# =========================
# Configuração inicial
# =========================

st.set_page_config(page_title="Validador NFCom 62", layout="wide")


# =========================
# Carregamento de arquivos de configuração
# =========================

@st.cache_data
def load_rules(path: str = "rules.yaml") -> List[Dict[str, Any]]:
    """Carrega as regras de validação a partir de um arquivo YAML."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            rules = yaml.safe_load(f) or []
    except FileNotFoundError:
        st.warning(f"Arquivo de regras '{path}' não encontrado. Nenhuma regra carregada.")
        rules = []
    return rules


@st.cache_data
def load_cclass_config(path: str = "cclass_config.yaml") -> Dict[str, Any]:
    """
    Carrega configuração de CClass (por exemplo, lista de CClass consideradas SVA).
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
    except FileNotFoundError:
        st.warning(f"Arquivo de configuração de CClass '{path}' não encontrado. Usando configuração padrão.")
        cfg = {}
    return cfg


# =========================
# Funções auxiliares XML
# =========================

def parse_xml(file_bytes: bytes) -> etree._ElementTree:
    """
    Faz o parse do XML e retorna um ElementTree.
    Lança ValueError se o arquivo não for XML válido.
    """
    try:
        parser = etree.XMLParser(remove_blank_text=True)
        tree = etree.parse(io.BytesIO(file_bytes), parser)
        return tree
    except Exception as e:
        raise ValueError(f"XML inválido: {e}")


def get_xpath_nodes(tree: etree._ElementTree, xpath: str):
    """
    Executa um XPath no XML e retorna a lista de nós encontrados.
    """
    root = tree.getroot()
    return root.xpath(xpath)


# =========================
# Motor genérico de regras (rules.yaml)
# =========================

import re


def apply_rule_to_node(rule: Dict[str, Any], node, file_name: str) -> List[Dict[str, Any]]:
    """
    Aplica uma regra simples (obrigatório, regex, lista_valores) a um nó específico.
    Retorna lista de dicionários de erros.
    """
    erros: List[Dict[str, Any]] = []
    rule_type = rule.get("tipo")

    if rule_type == "regex":
        texto = (node.text or "").strip()
        pattern = rule.get("parametros", {}).get("pattern", "")
        if pattern and not re.match(pattern, texto):
            erros.append({
                "arquivo": file_name,
                "regra_id": rule.get("id"),
                "descricao_regra": rule.get("descricao"),
                "campo_xpath": rule.get("xpath"),
                "valor_encontrado": texto,
                "mensagem_erro": rule.get("mensagem_erro"),
                "sugestao_correcao": rule.get("sugestao_correcao"),
                "nivel": rule.get("nivel", "erro"),
            })

    elif rule_type == "obrigatorio":
        texto = (node.text or "").strip() if node is not None else ""
        if not texto:
            erros.append({
                "arquivo": file_name,
                "regra_id": rule.get("id"),
                "descricao_regra": rule.get("descricao"),
                "campo_xpath": rule.get("xpath"),
                "valor_encontrado": texto,
                "mensagem_erro": rule.get("mensagem_erro"),
                "sugestao_correcao": rule.get("sugestao_correcao"),
                "nivel": rule.get("nivel", "erro"),
            })

    elif rule_type == "lista_valores":
        texto = (node.text or "").strip()
        valores_permitidos = rule.get("parametros", {}).get("valores_permitidos", [])
        if valores_permitidos and texto not in valores_permitidos:
            erros.append({
                "arquivo": file_name,
                "regra_id": rule.get("id"),
                "descricao_regra": rule.get("descricao"),
                "campo_xpath": rule.get("xpath"),
                "valor_encontrado": texto,
                "mensagem_erro": rule.get("mensagem_erro"),
                "sugestao_correcao": rule.get("sugestao_correcao"),
                "nivel": rule.get("nivel", "erro"),
            })

    return erros


def validate_with_rules_yaml(tree: etree._ElementTree, rules: List[Dict[str, Any]], file_name: str) -> List[Dict[str, Any]]:
    """
    Aplica todas as regras definidas em rules.yaml a um XML.
    Suporta tipos: obrigatorio, regex, lista_valores, condicional.
    """
    all_errors: List[Dict[str, Any]] = []

    for rule in rules:
        rule_type = rule.get("tipo")
        xpath = rule.get("xpath", "")
        params = rule.get("parametros", {}) or {}

        if rule_type == "condicional":
            base_xpath = xpath or ".//det"
            cond_xpath = params.get("condicao_xpath")
            cond_values = params.get("condicao_valores", [])
            alvo_xpath = params.get("alvo_xpath")
            alvo_valor_esperado = params.get("alvo_valor_esperado")

            base_nodes = get_xpath_nodes(tree, base_xpath)

            for base_node in base_nodes:
                cond_nodes = base_node.xpath(cond_xpath) if cond_xpath else []
                cond_text = (cond_nodes[0].text or "").strip() if cond_nodes else ""

                if cond_values and cond_text not in cond_values:
                    continue  # condição não atendida

                alvo_nodes = base_node.xpath(alvo_xpath) if alvo_xpath else []
                alvo_text = (alvo_nodes[0].text or "").strip() if alvo_nodes else ""

                erro = False

                # Se alvo_valor_esperado foi informado, testamos igualdade
                if alvo_valor_esperado is not None:
                    if alvo_text != str(alvo_valor_esperado):
                        erro = True
                else:
                    # Senão, apenas testamos se está preenchido (ou vazio) dependendo da regra
                    obrigatorio = params.get("alvo_obrigatorio", True)
                    if obrigatorio and not alvo_text:
                        erro = True
                    if not obrigatorio and alvo_text:
                        erro = True

                if erro:
                    all_errors.append({
                        "arquivo": file_name,
                        "regra_id": rule.get("id"),
                        "descricao_regra": rule.get("descricao"),
                        "campo_xpath": f"{base_xpath}/{alvo_xpath}",
                        "valor_encontrado": alvo_text,
                        "mensagem_erro": rule.get("mensagem_erro"),
                        "sugestao_correcao": rule.get("sugestao_correcao"),
                        "nivel": rule.get("nivel", "erro"),
                    })

        elif rule_type in ("obrigatorio", "regex", "lista_valores"):
            nodes = get_xpath_nodes(tree, xpath)
            if not nodes and rule_type == "obrigatorio":
                # Campo obrigatório ausente
                all_errors.append({
                    "arquivo": file_name,
                    "regra_id": rule.get("id"),
                    "descricao_regra": rule.get("descricao"),
                    "campo_xpath": xpath,
                    "valor_encontrado": "",
                    "mensagem_erro": rule.get("mensagem_erro"),
                    "sugestao_correcao": rule.get("sugestao_correcao"),
                    "nivel": rule.get("nivel", "erro"),
                })
            else:
                for node in nodes:
                    all_errors.extend(apply_rule_to_node(rule, node, file_name))

        # Tipos customizados podem ser tratados em outro ponto (funções específicas)

    return all_errors


# =========================
# Regras customizadas em Python
# =========================

def is_dest_non_contrib_pf(tree: etree._ElementTree) -> bool:
    """
    Heurística para identificar se o destinatário é PF ou PJ não contribuinte.
    Ajustar conforme o layout exato da NFCom.
    """
    root = tree.getroot()
    dest = root.find(".//dest")
    if dest is None:
        return False

    cpf = dest.findtext("CPF", "").strip()
    cnpj = dest.findtext("CNPJ", "").strip()
    ind_ie_dest = dest.findtext("indIEDest", "").strip()  # similar à NFe: 1=Contribuinte, 2=Isento, 9=Não Contribuinte

    # PF não contribuinte
    if cpf and (not ind_ie_dest or ind_ie_dest in ("2", "9")):
        return True

    # PJ não contribuinte de ICMS (CNPJ preenchido e indIEDest=9, por ex.)
    if cnpj and ind_ie_dest == "9":
        return True

    return False


def validate_cfop_pf_pj_nao_contrib(tree: etree._ElementTree, file_name: str) -> List[Dict[str, Any]]:
    """
    Regra:
    - Se destinatário for PF ou PJ não contribuinte de ICMS,
      então CFOP dos itens deve ser 5307 (interno) ou 6307 (interestadual).
    """
    erros: List[Dict[str, Any]] = []

    if not is_dest_non_contrib_pf(tree):
        return erros  # não se aplica

    root = tree.getroot()

    # Tenta identificar UF de emitente e destinatário para decidir entre 5307 / 6307.
    uf_emit = root.findtext(".//emit/enderEmit/UF", "").strip()
    uf_dest = root.findtext(".//dest/enderDest/UF", "").strip()

    cfop_corretos = []
    if uf_emit and uf_dest and uf_emit == uf_dest:
        cfop_corretos = ["5307"]
    else:
        cfop_corretos = ["6307"]

    det_nodes = root.xpath(".//det")
    for det in det_nodes:
        cfop = det.findtext("CFOP", "").strip()
        if cfop not in cfop_corretos:
            erros.append({
                "arquivo": file_name,
                "regra_id": "R_CFOP_PF_NCONTRIB",
                "descricao_regra": "CFOP para PF/PJ não contribuinte deve ser 5307 (interno) ou 6307 (interestadual)",
                "campo_xpath": ".//det/CFOP",
                "valor_encontrado": cfop,
                "mensagem_erro": f"CFOP '{cfop}' incompatível com destinatário PF/PJ não contribuinte.",
                "sugestao_correcao": f"Ajustar CFOP para {', '.join(cfop_corretos)} conforme UF do emitente e destinatário.",
                "nivel": "erro",
            })

    return erros


def validate_sva_cfop_zero(tree: etree._ElementTree, file_name: str, cclass_cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Regra:
    - Se o cClass do item for SVA, o CFOP deve estar 'zerado' (ex.: '0000').
    A lista de CClass considerados SVA vem de cclass_config.yaml.
    """
    erros: List[Dict[str, Any]] = []

    sva_cclasses = cclass_cfg.get("sva_cclasses", [])

    if not sva_cclasses:
        # Se não houver configuração, não valida (ou poderia emitir um aviso).
        return erros

    root = tree.getroot()
    det_nodes = root.xpath(".//det")

    for det in det_nodes:
        cclass = det.xpath("./serv/cClass")
        cclass_text = (cclass[0].text or "").strip() if cclass else ""

        if cclass_text not in sva_cclasses:
            continue  # não é SVA

        cfop = det.findtext("CFOP", "").strip()

        # Por padrão, consideramos CFOP 'zerado' como '0000'
        cfop_esperado = cclass_cfg.get("cfop_sva_zerado", "0000")

        if cfop != cfop_esperado:
            erros.append({
                "arquivo": file_name,
                "regra_id": "R_SVA_CFOP_ZERO",
                "descricao_regra": "Se cClass for SVA, CFOP deve estar zerado (ex.: 0000)",
                "campo_xpath": ".//det/CFOP",
                "valor_encontrado": cfop,
                "mensagem_erro": f"CFOP '{cfop}' incorreto para item SVA (cClass={cclass_text}).",
                "sugestao_correcao": f"Ajustar CFOP para '{cfop_esperado}' para itens com cClass SVA.",
                "nivel": "erro",
            })

    return erros


def validate_custom_rules(tree: etree._ElementTree, file_name: str, cclass_cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Aplica regras customizadas em Python que vão além do YAML.
    """
    erros: List[Dict[str, Any]] = []

    # CFOP para PF/PJ não contribuinte
    erros.extend(validate_cfop_pf_pj_nao_contrib(tree, file_name))

    # SVA com CFOP zerado
    erros.extend(validate_sva_cfop_zero(tree, file_name, cclass_cfg))

    # Espaço para incluir novas regras customizadas futuramente

    return erros


# =========================
# Extração para relatório de faturamento por CClass
# =========================

def extract_faturamento_items(tree: etree._ElementTree, file_name: str) -> List[Dict[str, Any]]:
    """
    Extrai informações de faturamento por item para posterior consolidação por CClass.
    Ajuste os XPaths conforme o layout exato da NFCom.
    """
    itens: List[Dict[str, Any]] = []

    root = tree.getroot()
    det_nodes = root.xpath(".//det")

    for det in det_nodes:
        cclass_nodes = det.xpath("./serv/cClass")
        cclass = (cclass_nodes[0].text or "").strip() if cclass_nodes else ""

        vserv_nodes = det.xpath("./serv/vServ")
        vserv_text = (vserv_nodes[0].text or "").strip() if vserv_nodes else "0"

        # Impostos (caminhos podem precisar de ajuste conforme o XML real)
        vicms_nodes = det.xpath(".//ICMS/vICMS")
        vpis_nodes = det.xpath(".//PIS/vPIS")
        vcofins_nodes = det.xpath(".//COFINS/vCOFINS")

        def to_float(value: str) -> float:
            try:
                # Tenta converter, trocando vírgula por ponto se necessário
                return float(value.replace(",", "."))
            except Exception:
                return 0.0

        item_data = {
            "arquivo": file_name,
            "cClass": cclass,
            "vServ": to_float(vserv_text),
            "vICMS": to_float((vicms_nodes[0].text or "").strip() if vicms_nodes else "0"),
            "vPIS": to_float((vpis_nodes[0].text or "").strip() if vpis_nodes else "0"),
            "vCOFINS": to_float((vcofins_nodes[0].text or "").strip() if vcofins_nodes else "0"),
        }
        itens.append(item_data)

    return itens


# =========================
# Interface Streamlit
# =========================

def main():
    st.title("Validador de NFCom modelo 62 (XML)")
    st.write(
        "Faça o upload de vários arquivos XML de NFCom e gere um relatório de "
        "erros de parametrização e tributação com base nas regras configuradas."
    )

    rules = load_rules()
    cclass_cfg = load_cclass_config()

    st.sidebar.header("Configurações")
    st.sidebar.write(f"Regras (YAML) carregadas: **{len(rules)}**")
    st.sidebar.write("CClass SVA configurados: **{}**".format(
        len(cclass_cfg.get("sva_cclasses", []))
    ))
    consolidar = st.sidebar.checkbox(
        "Consolidar erros iguais em um único agrupamento",
        value=True
    )

    uploaded_files = st.file_uploader(
        "Selecione um ou mais arquivos XML da NFCom",
        type=["xml"],
        accept_multiple_files=True
    )

    if uploaded_files and st.button("Validar arquivos"):
        todos_erros: List[Dict[str, Any]] = []
        erros_arquivos_invalidos: List[Dict[str, Any]] = []
        faturamento_itens: List[Dict[str, Any]] = []

        for f in uploaded_files:
            file_name = f.name
            try:
                content = f.read()
                tree = parse_xml(content)

                # Validações genéricas do YAML
                erros_yaml = validate_with_rules_yaml(tree, rules, file_name)
                todos_erros.extend(erros_yaml)

                # Regras customizadas em Python
                erros_custom = validate_custom_rules(tree, file_name, cclass_cfg)
                todos_erros.extend(erros_custom)

                # Dados para faturamento
                itens = extract_faturamento_items(tree, file_name)
                faturamento_itens.extend(itens)

            except ValueError as e:
                erros_arquivos_invalidos.append({
                    "arquivo": file_name,
                    "erro": str(e),
                })

        # Exibe arquivos inválidos
        if erros_arquivos_invalidos:
            st.subheader("Arquivos XML inválidos")
            df_invalidos = pd.DataFrame(erros_arquivos_invalidos)
            st.dataframe(df_invalidos, use_container_width=True)

        # Se não houver nenhum erro de regra
        if not todos_erros:
            st.success("Nenhum erro encontrado de acordo com as regras configuradas.")
        else:
            df_erros = pd.DataFrame(todos_erros)

            tab1, tab2, tab3 = st.tabs([
                "Erros detalhados por arquivo",
                "Erros consolidados",
                "Relatório de faturamento por CClass",
            ])

            with tab1:
                st.subheader("Relatório detalhado por arquivo")
                st.dataframe(df_erros, use_container_width=True)

                csv = df_erros.to_csv(index=False).encode("utf-8-sig")
                st.download_button(
                    "Baixar CSV detalhado de erros",
                    data=csv,
                    file_name="erros_nfcom_detalhado.csv",
                    mime="text/csv"
                )

            with tab2:
                st.subheader("Erros consolidados")
                if consolidar:
                    grouped = (
                        df_erros
                        .groupby([
                            "regra_id",
                            "descricao_regra",
                            "mensagem_erro",
                            "sugestao_correcao",
                            "nivel",
                        ])
                        .agg(
                            qtd_ocorrencias=("arquivo", "count"),
                            arquivos_afetados=("arquivo", lambda x: ", ".join(sorted(set(x)))),
                        )
                        .reset_index()
                    )
                    st.dataframe(grouped, use_container_width=True)

                    csv_g = grouped.to_csv(index=False).encode("utf-8-sig")
                    st.download_button(
                        "Baixar CSV consolidado de erros",
                        data=csv_g,
                        file_name="erros_nfcom_consolidado.csv",
                        mime="text/csv"
                    )
                else:
                    st.info("Marque a opção de consolidação na barra lateral para agrupar erros iguais.")

            with tab3:
                st.subheader("Relatório de faturamento por CClass")

                if not faturamento_itens:
                    st.info("Nenhum item de faturamento encontrado nos XML válidos.")
                else:
                    df_fat = pd.DataFrame(faturamento_itens)

                    # Agrupamento por cClass
                    df_agg = (
                        df_fat
                        .groupby("cClass")
                        .agg(
                            qtd_itens=("cClass", "count"),
                            total_vServ=("vServ", "sum"),
                            total_vICMS=("vICMS", "sum"),
                            total_vPIS=("vPIS", "sum"),
                            total_vCOFINS=("vCOFINS", "sum"),
                        )
                        .reset_index()
                    )

                    # Participação no faturamento
                    total_geral = df_agg["total_vServ"].sum()
                    if total_geral > 0:
                        df_agg["participacao_vServ_%"] = (df_agg["total_vServ"] / total_geral) * 100

                    st.dataframe(df_agg, use_container_width=True)

                    csv_fat = df_agg.to_csv(index=False).encode("utf-8-sig")
                    st.download_button(
                        "Baixar CSV de faturamento por CClass",
                        data=csv_fat,
                        file_name="faturamento_por_cclass.csv",
                        mime="text/csv"
                    )

    else:
        st.info("Faça o upload dos arquivos XML e clique em 'Validar arquivos' para iniciar a análise.")


if __name__ == "__main__":
    main()
