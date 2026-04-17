package eu.starsong.ghidra.service;

import eu.starsong.ghidra.dto.ClassDto;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Lookups for classes and namespaces derived from the symbol table.
 */
public class NamespaceService {

    public List<ClassDto> listClasses(Program program) {
        Set<String> classNames = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !ns.isGlobal() && ns.getSymbol().getSymbolType().isNamespace()) {
                classNames.add(ns.getName(true));
            }
        }
        List<String> sorted = new ArrayList<>(classNames);
        Collections.sort(sorted);
        return sorted.stream().map(ClassDto::fromQualifiedName).toList();
    }

    public List<String> listNamespaces(Program program) {
        Set<String> namespaces = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !(ns instanceof GlobalNamespace)) {
                namespaces.add(ns.getName(true));
            }
        }
        List<String> sorted = new ArrayList<>(namespaces);
        Collections.sort(sorted);
        return sorted;
    }
}
